package local.chatgpt.tlsfix;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/** A process- and hostname-scoped port of the temporary Frida experiment. */
public final class TlsHook implements IXposedHookLoadPackage {
    private static final String TARGET = "com.openai.chatgpt";
    private static final AtomicInteger EVENTS = new AtomicInteger();

    static boolean allowedHost(String hostname) {
        if (hostname == null) return false;
        String host = hostname.toLowerCase(Locale.ROOT);
        for (String domain : new String[]{"chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com"}) {
            if (host.equals(domain) || host.endsWith("." + domain)) return true;
        }
        return false;
    }

    private static void log(String message) {
        XposedBridge.log("[ChatGPT-TLS] " + message);
    }

    private static void event(String message) {
        if (EVENTS.getAndIncrement() < 30) log(message);
    }

    @Override public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lp) {
        if (!TARGET.equals(lp.packageName)) return;
        log("loaded v1.0 process=" + lp.processName);
        hookConscrypt(lp.classLoader);
        hookCronet(lp.classLoader);
    }

    private static void hookConscrypt(ClassLoader loader) {
        Class<?> type = XposedHelpers.findClassIfExists("com.android.org.conscrypt.TrustManagerImpl", loader);
        if (type == null) { log("Conscrypt unavailable"); return; }
        int count = XposedBridge.hookAllMethods(type, "verifyChain", new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam p) {
                if (p.args.length < 3 || !(p.args[2] instanceof String)) return;
                String host = (String) p.args[2];
                if (!allowedHost(host) || !p.hasThrowable()) return;
                // Preserve normal verification. Only replace certificate failures.
                if (!(p.getThrowable() instanceof CertificateException)) return;
                if (!(p.args[0] instanceof List) || ((List<?>) p.args[0]).isEmpty()) return;
                p.setResult(p.args[0]);
                event("Conscrypt certificate failure bypassed host=" + host);
            }
        }).size();
        log("Conscrypt hooks=" + count);
    }

    private static void hookCronet(final ClassLoader loader) {
        Class<?> type = XposedHelpers.findClassIfExists("org.chromium.net.X509Util", loader);
        if (type == null) { log("Cronet unavailable"); return; }
        int count = XposedBridge.hookAllMethods(type, "verifyServerCertificates", new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args.length < 3 || !(p.args[2] instanceof String) || !(p.args[0] instanceof byte[][])) return;
                String host = (String) p.args[2];
                if (!allowedHost(host) || p.hasThrowable() || p.getResult() == null) return;
                Object original = p.getResult();
                int status = (Integer) XposedHelpers.callMethod(original, "getStatus");
                if (status == 0) { event("Cronet certificate accepted host=" + host); return; }
                byte[][] encoded = (byte[][]) p.args[0];
                if (encoded.length == 0) return;
                List<X509Certificate> chain = new ArrayList<>();
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                for (byte[] cert : encoded) {
                    chain.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(cert)));
                }
                Object result = XposedHelpers.newInstance(original.getClass(), 0, true, chain);
                p.setResult(result);
                event("Cronet certificate failure bypassed host=" + host + " originalStatus=" + status);
            }
        }).size();
        log("Cronet hooks=" + count);
    }
}
