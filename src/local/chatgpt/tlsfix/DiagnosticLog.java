package local.chatgpt.tlsfix;

import android.util.Log;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import de.robv.android.xposed.XposedBridge;

/** No-throw, bounded diagnostic sink. Counts survive suppression and sink errors. */
final class DiagnosticLog {
    private static final String TAG = "ChatGPT-TLS";
    private static final String SESSION = UUID.randomUUID().toString().substring(0, 12);
    private static final AtomicLong SEQUENCE = new AtomicLong();
    private static final AtomicLong INVOCATIONS = new AtomicLong();
    private static final ThreadLocal<Boolean> SELF_TEST = new ThreadLocal<>();
    private static final ThreadLocal<String> INVOCATION = new ThreadLocal<>();
    private static final ThreadLocal<Boolean> EMITTING = new ThreadLocal<>();
    private static final Object LOCK = new Object();
    private static final Map<String, Long> COUNTS = new LinkedHashMap<>();
    private static final Map<String, Long> SUPPRESSED = new LinkedHashMap<>();
    private static final Map<String, Window> WINDOWS = new LinkedHashMap<>();
    private static boolean summariesStarted;

    private static final class Window { long started = System.nanoTime(); int used; }

    static void beginSelfTest() { SELF_TEST.set(Boolean.TRUE); }
    static void endSelfTest() { SELF_TEST.remove(); }
    static String beginInvocation() {
        String previous = INVOCATION.get();
        INVOCATION.set(SESSION + ":" + INVOCATIONS.incrementAndGet());
        return previous;
    }
    static void endInvocation(String previous) {
        if (previous == null) INVOCATION.remove(); else INVOCATION.set(previous);
    }
    static Map<String, Long> countersSnapshot() {
        synchronized (LOCK) { return new LinkedHashMap<>(COUNTS); }
    }

    static void startSummaries() {
        try {
            synchronized (LOCK) {
                if (summariesStarted) return;
                summariesStarted = true;
            }
            ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
                @Override public Thread newThread(Runnable task) {
                    Thread thread = new Thread(task, "ChatGPT-TLS-summary");
                    thread.setDaemon(true);
                    return thread;
                }
            });
            scheduler.scheduleAtFixedRate(new Runnable() {
                @Override public void run() { emit("summary", "module", null, "cumulative_counts", null, null, null); }
            }, 30, 30, TimeUnit.SECONDS);
        } catch (Throwable ignored) { }
    }

    static void emit(String event, String backend, String host, String outcome,
            Throwable error, Integer status, List<?> chain) {
        if (Boolean.TRUE.equals(EMITTING.get())) return;
        try {
            EMITTING.set(Boolean.TRUE);
            String source = Boolean.TRUE.equals(SELF_TEST.get()) ? "self_test" : "live";
            String key = source + "." + event;
            synchronized (LOCK) {
                COUNTS.put(key, value(COUNTS, key) + 1);
                if (!"summary".equals(event) && !allow(key, event)) {
                    SUPPRESSED.put(key, value(SUPPRESSED, key) + 1);
                    return;
                }
            }
            Map<String, Object> record = new LinkedHashMap<>();
            record.put("schema", 1);
            record.put("version", "1.2");
            record.put("session", SESSION);
            record.put("seq", SEQUENCE.incrementAndGet());
            record.put("time_ms", System.currentTimeMillis());
            record.put("pid", android.os.Process.myPid());
            record.put("thread_id", Thread.currentThread().getId());
            record.put("source", source);
            record.put("event", event);
            record.put("backend", backend);
            if (INVOCATION.get() != null) record.put("invocation_id", INVOCATION.get());
            if (host != null) record.put("host", TlsHook.allowedHost(host) ? host.toLowerCase(Locale.ROOT) : "<out-of-scope>");
            record.put("outcome", outcome);
            if (status != null) record.put("original_status", status);
            if (error != null) {
                record.put("exception_types", exceptionTypes(error));
                record.put("reason", reason(error));
            }
            if (chain != null) addCertificateMetadata(record, chain);
            if ("summary".equals(event)) {
                synchronized (LOCK) {
                    record.put("counts", new LinkedHashMap<>(COUNTS));
                    record.put("suppressed", new LinkedHashMap<>(SUPPRESSED));
                }
            }
            String line = "[" + TAG + "] " + json(record);
            try { XposedBridge.log(line); } catch (Throwable ignored) { }
            try { Log.i(TAG, line); } catch (Throwable ignored) { }
        } catch (Throwable ignored) {
            // Never expose raw exception text or recursively log logger failures.
        } finally { EMITTING.remove(); }
    }

    private static long value(Map<String, Long> map, String key) {
        Long current = map.get(key);
        return current == null ? 0L : current;
    }
    private static boolean allow(String key, String event) {
        Window window = WINDOWS.get(key);
        if (window == null) { window = new Window(); WINDOWS.put(key, window); }
        long now = System.nanoTime();
        if (now - window.started >= TimeUnit.SECONDS.toNanos(60)) { window.started = now; window.used = 0; }
        int limit = "verification_accepted".equals(event) ? 12
                : "verification_skipped".equals(event) ? 12
                : "handshake_exception".equals(event) ? 24 : 48;
        return window.used++ < limit;
    }
    private static List<String> exceptionTypes(Throwable error) {
        List<String> types = new ArrayList<>();
        Throwable current = error;
        for (int i = 0; current != null && i < 8; i++) {
            types.add(bounded(current.getClass().getName(), 160));
            Throwable next = current.getCause();
            if (next == current) break;
            current = next;
        }
        return types;
    }
    private static String reason(Throwable error) {
        Throwable current = error;
        for (int i = 0; current != null && i < 8; i++) {
            if (current instanceof java.security.cert.CertificateExpiredException) return "certificate_expired";
            if (current instanceof java.security.cert.CertificateNotYetValidException) return "certificate_not_yet_valid";
            String message = current.getMessage();
            if (message != null) {
                String m = message.substring(0, Math.min(message.length(), 2048)).toLowerCase(Locale.ROOT);
                if (m.contains("trust anchor")) return "trust_anchor_missing";
                if (m.contains("pinning") || m.contains("blocked public key")) return "public_key_rejected";
                if (m.contains("hostname") || m.contains("subject alternative")) return "hostname_mismatch";
                if (m.contains("eof") || m.contains("closed") || m.contains("terminated") || m.contains("reset")) return "handshake_terminated";
                if (m.contains("timed out") || m.contains("timeout")) return "timeout";
            }
            Throwable next = current.getCause();
            if (next == current) break;
            current = next;
        }
        return "unspecified";
    }
    private static void addCertificateMetadata(Map<String, Object> record, List<?> chain) {
        try {
            record.put("chain_length", chain.size());
            if (chain.isEmpty()) return;
            Object leaf = chain.get(0);
            X509Certificate certificate = null;
            if (leaf instanceof X509Certificate) certificate = (X509Certificate) leaf;
            if (leaf instanceof byte[]) certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream((byte[]) leaf));
            if (certificate == null) { record.put("certificate_metadata", "unsupported_leaf_type"); return; }
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("subject", bounded(certificate.getSubjectX500Principal().getName(), 192));
            metadata.put("issuer", bounded(certificate.getIssuerX500Principal().getName(), 192));
            metadata.put("not_before_ms", certificate.getNotBefore().getTime());
            metadata.put("not_after_ms", certificate.getNotAfter().getTime());
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) hex.append(String.format(Locale.ROOT, "%02x", b & 0xff));
            metadata.put("sha256", hex.toString());
            record.put("leaf", metadata);
        } catch (Throwable ignored) { record.put("certificate_metadata", "unavailable_or_malformed"); }
    }
    private static String bounded(String text, int max) {
        if (text == null) return "";
        return text.length() <= max ? text : text.substring(0, max) + "...";
    }
    private static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        StringBuilder out = new StringBuilder();
        if (value instanceof Map) {
            out.append('{');
            for (Object entryObject : ((Map<?, ?>) value).entrySet()) {
                Map.Entry<?, ?> entry = (Map.Entry<?, ?>) entryObject;
                if (out.length() > 1) out.append(',');
                out.append(json(String.valueOf(entry.getKey()))).append(':').append(json(entry.getValue()));
            }
            return out.append('}').toString();
        }
        if (value instanceof Iterable) {
            out.append('[');
            for (Object item : (Iterable<?>) value) {
                if (out.length() > 1) out.append(',');
                out.append(json(item));
            }
            return out.append(']').toString();
        }
        out.append('"');
        String text = String.valueOf(value);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '"' || c == '\\') out.append('\\').append(c);
            else if (c < 32) out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
            else out.append(c);
        }
        return out.append('"').toString();
    }
}
