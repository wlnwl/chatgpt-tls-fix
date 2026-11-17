package local.chatgpt.tlsfix;

import java.io.EOFException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertPathValidatorException;
import java.util.ArrayDeque;
import java.util.IdentityHashMap;
import java.util.Locale;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;

/** Conservative classification only; never edits an exception or TLS verification result. */
final class TransportFailureClassifier {
    private static final int MAX_ERRORS = 64;
    static String classify(Throwable error) {
        if (error == null) return null;
        try {
            ArrayDeque<Throwable> pending = new ArrayDeque<>();
            IdentityHashMap<Throwable, Boolean> visited = new IdentityHashMap<>();
            pending.add(error);
            boolean handshake = false;
            String transport = null;
            while (!pending.isEmpty()) {
                Throwable current = pending.removeFirst();
                if (visited.put(current, Boolean.TRUE) != null) return null;
                if (visited.size() > MAX_ERRORS) return null;
                if (current instanceof GeneralSecurityException || current instanceof CertificateException || current instanceof CertPathValidatorException
                        || current instanceof SSLPeerUnverifiedException) return null;
                String message = current.getMessage();
                // An oversized or inaccessible message cannot be completely excluded as certificate evidence.
                if (message != null && message.length() > 4096) return null;
                String text = message == null ? "" : message.toLowerCase(Locale.ROOT);
                if (contains(text, "certificate", "certification", "certpath", "cert_", "hostname", "host name",
                        "trust anchor", "trustmanager", "pinning", "pinned", "public key", "unknown ca",
                        "fatal alert", "handshake_failure", "protocol_version", "cipher suite")) return null;
                if (current instanceof SSLHandshakeException) handshake = true;
                if (current instanceof EOFException) transport = "eof";
                else if (current instanceof SocketTimeoutException) transport = "timeout";
                else if (current instanceof SocketException || current instanceof SSLHandshakeException) {
                    if (contains(text, "connection reset", "connection was reset", "broken pipe")) transport = "connection_reset";
                    else if (contains(text, "unexpected eof", "end of stream", "peer shut down incorrectly")) transport = "eof";
                    else if (contains(text, "remote host terminated", "connection closed", "socket closed", "connection has been shutdown")) transport = "connection_closed";
                    else if (contains(text, "timed out", "timeout")) transport = "timeout";
                }
                Throwable cause = current.getCause();
                Throwable[] suppressed = current.getSuppressed();
                int remaining = MAX_ERRORS - visited.size() - pending.size();
                if (suppressed.length > remaining - (cause == null ? 0 : 1)) return null;
                if (cause != null) pending.add(cause);
                for (Throwable item : suppressed) pending.add(item);
            }
            return handshake ? transport : null;
        } catch (Throwable inspectionFailure) { return null; }
    }
    private static boolean contains(String text, String... terms) {
        for (String term : terms) if (text.contains(term)) return true;
        return false;
    }
}
