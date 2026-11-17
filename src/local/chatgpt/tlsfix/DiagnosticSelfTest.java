package local.chatgpt.tlsfix;

import android.app.Application;
import android.content.Context;
import java.io.*;
import java.lang.reflect.*;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.*;
import de.robv.android.xposed.*;

/** Explicit, one-shot local verification test. Never opens a socket or installs a CA. */
final class DiagnosticSelfTest {
    private static final String REQUEST = "chatgpt-tlsfix-selftest.request";
    private static final AtomicBoolean STARTED = new AtomicBoolean();
    private static final ThreadLocal<Boolean> PRESERVE_CONSCRYPT = new ThreadLocal<>();
    private static int failures;

    static boolean preserveConscryptForSelfTest() { return Boolean.TRUE.equals(PRESERVE_CONSCRYPT.get()); }

    static void install(final ClassLoader loader) {
        try {
            XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class, new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    try {
                        Context context = (Context) p.args[0];
                        if (!"com.openai.chatgpt".equals(context.getPackageName())) return;
                        File request = new File(context.getCacheDir(), REQUEST);
                        if (!request.isFile() || request.length() > 32) return;
                        String token;
                        try (BufferedReader reader = new BufferedReader(new FileReader(request))) {
                            token = reader.readLine();
                        }
                        if (!"v1.2".equals(token) || !request.delete() || !STARTED.compareAndSet(false, true)) return;
                        Thread worker = new Thread(new Runnable() {
                            @Override public void run() { execute(loader); }
                        }, "tlsfix-selftest");
                        worker.setDaemon(true);
                        // Run after Application.onCreate has initialized Cronet's application context.
                        new android.os.Handler(context.getMainLooper()).postDelayed(new Runnable() {
                            @Override public void run() { worker.start(); }
                        }, 2000);
                    } catch (Throwable error) {
                        DiagnosticLog.emit("self_test_setup_error", "selftest", null, "not_run", error, null, null);
                    }
                }
            });
        } catch (Throwable error) {
            DiagnosticLog.emit("hook_error", "selftest", null, "attach_unavailable", error, null, null);
        }
    }

    private static void check(String test, boolean passed, Throwable error) {
        if (!passed) failures++;
        DiagnosticLog.emit("self_test_assert", test, null, passed ? "pass" : "fail", error, null, null);
        if (!passed && error != null) {
            StackTraceElement[] frames = error.getStackTrace();
            for (int i = 0; i < Math.min(4, frames.length); i++) {
                DiagnosticLog.emit("self_test_error_location", test, null,
                        frames[i].getClassName() + "." + frames[i].getMethodName() + ":" + frames[i].getLineNumber(), null, null, null);
            }
        }
    }

    private static long count(String name) {
        Long value = DiagnosticLog.countersSnapshot().get("self_test." + name);
        return value == null ? 0 : value;
    }

    private static Throwable unwrap(Throwable t) {
        while (t instanceof InvocationTargetException && t.getCause() != null) t = t.getCause();
        return t;
    }

    private static void execute(ClassLoader loader) {
        DiagnosticLog.beginSelfTest();
        try {
            byte[] der = Base64.getDecoder().decode(SelfTestCertificate.DER_BASE64);
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
            List<X509Certificate> chain = Collections.singletonList(cert);
            DiagnosticLog.emit("self_test_started", "selftest", "diagnostic.chatgpt.com", "local_no_network", null, null, chain);
            testConscrypt(chain);
            testCronet(loader, der);
            long before = count("handshake_exception");
            new SSLHandshakeException("controlled self-test; no socket opened");
            check("handshake_observer", count("handshake_exception") > before, null);
        } catch (Throwable t) {
            check("selftest_runtime", false, unwrap(t));
        } finally {
            DiagnosticLog.emit("self_test_complete", "selftest", null, failures == 0 ? "pass" : "fail", null, failures, null);
            DiagnosticLog.endSelfTest();
        }
    }

    private static void testConscrypt(List<X509Certificate> chain) {
        try {
            KeyStore emptyStore = KeyStore.getInstance("PKCS12");
            emptyStore.load(null, null);
            Object manager = Class.forName("com.android.org.conscrypt.TrustManagerImpl")
                    .getConstructor(KeyStore.class).newInstance(emptyStore);
            Method method = null;
            for (Class<?> type = manager.getClass(); type != null; type = type.getSuperclass()) {
                for (Method item : type.getDeclaredMethods()) {
                    if (item.getName().equals("verifyChain") && item.getParameterTypes().length == 6) method = item;
                }
            }
            if (method == null) throw new NoSuchMethodException("verifyChain/6");
            method.setAccessible(true);
            Object[] args = {chain, Collections.emptyList(), "diagnostic.chatgpt.com", false, null, null};
            Throwable baseline = null;
            try { XposedBridge.invokeOriginalMethod(method, manager, args); } catch (Throwable t) { baseline = unwrap(t); }
            check("conscrypt_original_rejects", baseline instanceof CertificateException, baseline);
            long failed = count("verification_failed"), bypassed = count("verification_bypassed");
            Object result = method.invoke(manager, args);
            check("conscrypt_failed_then_bypassed", result == chain && count("verification_failed") > failed
                    && count("verification_bypassed") > bypassed, null);
            args[2] = "diagnostic.invalid";
            Throwable rejected = null;
            try { method.invoke(manager, args); } catch (Throwable t) { rejected = unwrap(t); }
            check("conscrypt_out_of_scope_preserved", rejected instanceof CertificateException, rejected);
            args[0] = Collections.emptyList();
            args[1] = Collections.singletonList(new TrustAnchor(chain.get(0), null));
            args[2] = "diagnostic.chatgpt.com";
            bypassed = count("verification_bypassed");
            result = method.invoke(manager, args);
            check("conscrypt_valid_unchanged", result instanceof List && ((List<?>) result).size() == 1
                    && count("verification_bypassed") == bypassed, null);
        } catch (Throwable t) { check("conscrypt_runtime", false, unwrap(t)); }
    }

    private static void testCronet(ClassLoader loader, byte[] der) {
        // Do not let the lower-level compatibility hook mask the real Cronet rejection.
        PRESERVE_CONSCRYPT.set(true);
        try {
            Class<?> type = XposedHelpers.findClass("org.chromium.net.X509Util", loader);
            Method method;
            Object[] args;
            try {
                method = type.getDeclaredMethod("verifyServerCertificates", byte[][].class, String.class, String.class, byte[].class, byte[].class);
                args = new Object[]{new byte[][]{der}, "RSA", "diagnostic.chatgpt.com", new byte[0], new byte[0]};
            } catch (NoSuchMethodException olderSignature) {
                method = type.getDeclaredMethod("verifyServerCertificates", byte[][].class, String.class, String.class);
                args = new Object[]{new byte[][]{der}, "RSA", "diagnostic.chatgpt.com"};
            }
            method.setAccessible(true);
            Object original = null;
            Throwable baselineError = null;
            try { original = XposedBridge.invokeOriginalMethod(method, null, args); }
            catch (Throwable t) { baselineError = unwrap(t); }
            if (baselineError != null) {
                // Some shipped Cronet builds retain an unused verifier whose parser throws.
                // Verify exception preservation on that real method; never fabricate a success.
                DiagnosticLog.emit("self_test_capability", "cronet", null, "original_verifier_throws", baselineError, null, null);
                check("cronet_original_throw_observed", true, baselineError);
                long failedBefore = count("verification_failed"), bypassedBefore = count("verification_bypassed");
                Throwable hookedError = null;
                try { method.invoke(null, args); } catch (Throwable t) { hookedError = unwrap(t); }
                check("cronet_throw_logged_and_preserved", hookedError != null
                        && hookedError.getClass() == baselineError.getClass()
                        && count("verification_failed") > failedBefore
                        && count("verification_bypassed") == bypassedBefore, hookedError);
                args[2] = "diagnostic.invalid";
                Throwable outOfScopeError = null;
                try { method.invoke(null, args); } catch (Throwable t) { outOfScopeError = unwrap(t); }
                check("cronet_out_of_scope_throw_preserved", outOfScopeError != null
                        && outOfScopeError.getClass() == baselineError.getClass(), outOfScopeError);
                return;
            }
            int status = (Integer) XposedHelpers.callMethod(original, "getStatus");
            check("cronet_original_rejects", status != 0, null);
            long failed = count("verification_failed"), bypassed = count("verification_bypassed");
            Object result = method.invoke(null, args);
            check("cronet_failed_then_bypassed", (Integer) XposedHelpers.callMethod(result, "getStatus") == 0
                    && count("verification_failed") > failed && count("verification_bypassed") > bypassed, null);
            args[2] = "diagnostic.invalid";
            result = method.invoke(null, args);
            check("cronet_out_of_scope_preserved", (Integer) XposedHelpers.callMethod(result, "getStatus") != 0, null);
        } catch (Throwable t) { check("cronet_runtime", false, unwrap(t)); }
        finally { PRESERVE_CONSCRYPT.remove(); }
    }
}
