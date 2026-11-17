package local.chatgpt.tlsfix;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLHandshakeException;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/** Existing package/domain-scoped compatibility hooks, with isolated diagnostics. */
public final class TlsHook implements IXposedHookLoadPackage {
    private static final String TARGET = "com.openai.chatgpt";

    static boolean allowedHost(String hostname) {
        if (hostname == null || hostname.length() == 0 || hostname.length() > 253) return false;
        for (int i = 0; i < hostname.length(); i++) {
            char c = hostname.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '.')) return false;
        }
        String host = hostname.toLowerCase(Locale.ROOT);
        for (String label : host.split("\\.", -1)) {
            if (label.length() == 0 || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) return false;
        }
        for (String domain : new String[]{"chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com"}) {
            if (host.equals(domain) || host.endsWith("." + domain)) return true;
        }
        return false;
    }

    @Override public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lp) {
        if (!TARGET.equals(lp.packageName)) return;
        DiagnosticLog.emit("loaded", "module", null, "version_1.2", null, null, null);
        DiagnosticLog.startSummaries();
        hookConscrypt(lp.classLoader);
        hookCronet(lp.classLoader);
        hookHandshakeExceptions();
        TransportErrorGuard.install(lp.classLoader);
        try { DiagnosticSelfTest.install(lp.classLoader); }
        catch (Throwable error) { DiagnosticLog.emit("hook_error", "self_test", null, "install_failed", error, null, null); }
    }

    private static void hookConscrypt(ClassLoader loader) {
        try {
            Class<?> type = XposedHelpers.findClassIfExists("com.android.org.conscrypt.TrustManagerImpl", loader);
            if (type == null) {
                DiagnosticLog.emit("hook_missing", "conscrypt", null, "class_unavailable", null, null, null);
                return;
            }
            int count = XposedBridge.hookAllMethods(type, "verifyChain", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    String previous = DiagnosticLog.beginInvocation();
                    String host = null;
                    List<?> chain = null;
                    try {
                        if (p.args == null || p.args.length < 3 || !(p.args[2] instanceof String)) {
                            DiagnosticLog.emit("verification_skipped", "conscrypt", null, "invalid_arguments", null, null, null);
                            return;
                        }
                        host = (String) p.args[2];
                        if (!allowedHost(host)) {
                            DiagnosticLog.emit("verification_skipped", "conscrypt", host, "out_of_scope", null, null, null);
                            return;
                        }
                        if (p.args[0] instanceof List) chain = (List<?>) p.args[0];
                        if (!p.hasThrowable()) {
                            DiagnosticLog.emit("verification_accepted", "conscrypt", host, "original_success", null, null, chain);
                            return;
                        }
                        Throwable originalError = p.getThrowable();
                        DiagnosticLog.emit("verification_failed", "conscrypt", host, "original_threw", originalError, null, chain);
                        if (DiagnosticSelfTest.preserveConscryptForSelfTest()) {
                            DiagnosticLog.emit("verification_skipped", "conscrypt", host, "self_test_baseline", originalError, null, chain);
                            return;
                        }
                        // Keep v1 eligibility: only this method's CertificateException and nonempty List.
                        if (!(originalError instanceof CertificateException)) {
                            DiagnosticLog.emit("verification_skipped", "conscrypt", host, "non_certificate_exception", originalError, null, chain);
                            return;
                        }
                        if (chain == null || chain.isEmpty()) {
                            DiagnosticLog.emit("verification_skipped", "conscrypt", host, "empty_chain", originalError, null, chain);
                            return;
                        }
                        p.setResult(p.args[0]);
                        DiagnosticLog.emit("verification_bypassed", "conscrypt", host, "returned_original_chain", originalError, null, chain);
                    } catch (Throwable error) {
                        DiagnosticLog.emit("hook_error", "conscrypt", host, "preserved_original", error, null, chain);
                    } finally { DiagnosticLog.endInvocation(previous); }
                }
            }).size();
            DiagnosticLog.emit(count == 0 ? "hook_missing" : "hook_registered", "conscrypt", null,
                    "method_count_" + count, null, null, null);
        } catch (Throwable error) { DiagnosticLog.emit("hook_error", "conscrypt", null, "registration_failed", error, null, null); }
    }

    private static void hookCronet(ClassLoader loader) {
        try {
            Class<?> type = XposedHelpers.findClassIfExists("org.chromium.net.X509Util", loader);
            if (type == null) {
                DiagnosticLog.emit("hook_missing", "cronet", null, "class_unavailable", null, null, null);
                return;
            }
            int count = XposedBridge.hookAllMethods(type, "verifyServerCertificates", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    String previous = DiagnosticLog.beginInvocation();
                    String host = null;
                    List<?> observed = null;
                    Integer status = null;
                    try {
                        if (p.args == null || p.args.length < 3 || !(p.args[2] instanceof String)
                                || !(p.args[0] instanceof byte[][])) {
                            DiagnosticLog.emit("verification_skipped", "cronet", null, "invalid_arguments", null, null, null);
                            return;
                        }
                        host = (String) p.args[2];
                        if (!allowedHost(host)) {
                            DiagnosticLog.emit("verification_skipped", "cronet", host, "out_of_scope", null, null, null);
                            return;
                        }
                        byte[][] encoded = (byte[][]) p.args[0];
                        observed = Arrays.asList(encoded);
                        if (p.hasThrowable()) {
                            DiagnosticLog.emit("verification_failed", "cronet", host, "original_threw", p.getThrowable(), null, observed);
                            DiagnosticLog.emit("verification_skipped", "cronet", host, "original_throwable_preserved", p.getThrowable(), null, null);
                            return;
                        }
                        Object original = p.getResult();
                        if (original == null) {
                            DiagnosticLog.emit("verification_skipped", "cronet", host, "null_result", null, null, observed);
                            return;
                        }
                        status = (Integer) XposedHelpers.callMethod(original, "getStatus");
                        if (status == 0) {
                            DiagnosticLog.emit("verification_accepted", "cronet", host, "original_success", null, status, observed);
                            return;
                        }
                        DiagnosticLog.emit("verification_failed", "cronet", host, "original_status_failure", null, status, observed);
                        if (encoded.length == 0) {
                            DiagnosticLog.emit("verification_skipped", "cronet", host, "empty_chain", null, status, observed);
                            return;
                        }
                        List<X509Certificate> chain = new ArrayList<>();
                        CertificateFactory factory = CertificateFactory.getInstance("X.509");
                        for (byte[] cert : encoded) chain.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(cert)));
                        // Construction/parsing must finish before mutating the original result.
                        Object result = XposedHelpers.newInstance(original.getClass(), 0, true, chain);
                        p.setResult(result);
                        DiagnosticLog.emit("verification_bypassed", "cronet", host, "replaced_status_with_success", null, status, chain);
                    } catch (Throwable error) {
                        DiagnosticLog.emit("hook_error", "cronet", host, "preserved_original", error, status, observed);
                    } finally { DiagnosticLog.endInvocation(previous); }
                }
            }).size();
            DiagnosticLog.emit(count == 0 ? "hook_missing" : "hook_registered", "cronet", null,
                    "method_count_" + count, null, null, null);
        } catch (Throwable error) { DiagnosticLog.emit("hook_error", "cronet", null, "registration_failed", error, null, null); }
    }

    private static void hookHandshakeExceptions() {
        try {
            int count = XposedBridge.hookAllConstructors(SSLHandshakeException.class, new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    // Observes construction only. Never changes or claims the exception was thrown.
                    if (p.thisObject instanceof Throwable) DiagnosticLog.emit("handshake_exception", "javax.net.ssl", null,
                            "constructed_not_necessarily_thrown", (Throwable) p.thisObject, null, null);
                }
            }).size();
            DiagnosticLog.emit(count == 0 ? "hook_missing" : "hook_registered", "handshake", null,
                    "constructor_count_" + count, null, null, null);
        } catch (Throwable error) { DiagnosticLog.emit("hook_error", "handshake", null, "registration_failed", error, null, null); }
    }
}
