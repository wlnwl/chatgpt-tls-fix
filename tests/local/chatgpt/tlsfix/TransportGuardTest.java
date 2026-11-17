package local.chatgpt.tlsfix;

import java.io.EOFException;
import java.io.IOException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.cert.CertificateException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathBuilderException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;

/** Actual conservative classifier and state-scoping regressions, no network or fake request successes. */
public final class TransportGuardTest {
    private static int passed;
    private static final class ErrorState {}
    private static final class NormalState {}
    private interface Test { void run() throws Throwable; }
    private static SSLHandshakeException handshake(Throwable cause) {
        SSLHandshakeException error = new SSLHandshakeException("handshake failed");
        if (cause != null) error.initCause(cause);
        return error;
    }
    private static void check(boolean ok) { if (!ok) throw new AssertionError(); }
    private static void run(String name, Test action) throws Throwable { action.run(); passed++; System.out.println("PASS guard " + name); }
    public static void main(String[] args) throws Throwable {
        run("EOF handshake accepted", () -> check("eof".equals(TransportFailureClassifier.classify(handshake(new EOFException())))));
        run("reset handshake accepted", () -> check("connection_reset".equals(TransportFailureClassifier.classify(handshake(new SocketException("Connection reset"))))));
        run("timeout handshake accepted", () -> check("timeout".equals(TransportFailureClassifier.classify(handshake(new SocketTimeoutException())))));
        run("specific terminated peer message accepted", () -> check("connection_closed".equals(TransportFailureClassifier.classify(new SSLHandshakeException("Remote host terminated the handshake")))));
        run("outer wrapper retains nested transport evidence", () -> check("eof".equals(TransportFailureClassifier.classify(new IOException(handshake(new EOFException()))))));
        run("non-handshake EOF rejected", () -> check(TransportFailureClassifier.classify(new EOFException()) == null));
        run("unknown handshake rejected", () -> check(TransportFailureClassifier.classify(handshake(null)) == null));
        run("certificate inside EOF cause wins", () -> { EOFException eof = new EOFException(); eof.initCause(new CertificateException()); check(TransportFailureClassifier.classify(handshake(eof)) == null); });
        run("suppressed certificate wins", () -> { Throwable error = handshake(new EOFException()); error.addSuppressed(new CertificateException()); check(TransportFailureClassifier.classify(error) == null); });
        run("certificate path failure wins", () -> { Throwable error=handshake(new EOFException()); error.addSuppressed(new CertPathValidatorException()); check(TransportFailureClassifier.classify(error)==null); });
        run("certificate path builder failure wins", () -> { Throwable error=new SSLHandshakeException("unexpected EOF"); error.addSuppressed(new CertPathBuilderException("unable to find valid certification path")); check(TransportFailureClassifier.classify(error)==null); });
        run("peer identity failure wins", () -> { Throwable error=handshake(new EOFException()); error.addSuppressed(new SSLPeerUnverifiedException("peer")); check(TransportFailureClassifier.classify(error)==null); });
        run("pinning message wins over closed text", () -> check(TransportFailureClassifier.classify(new SSLHandshakeException("connection closed: pinning failed"))==null));
        run("hostname message wins over reset text", () -> check(TransportFailureClassifier.classify(new SSLHandshakeException("connection reset: hostname mismatch"))==null));
        run("trust failure message wins over EOF", () -> check(TransportFailureClassifier.classify(new SSLHandshakeException("unexpected EOF: trust anchor missing"))==null));
        run("fatal TLS alert is not treated as transport", () -> check(TransportFailureClassifier.classify(new SSLHandshakeException("connection closed: fatal alert handshake_failure"))==null));
        run("bounded scan rejects incomplete chain", () -> { Throwable error=new EOFException(); for(int i=0;i<70;i++) error=new IOException(error); check(TransportFailureClassifier.classify(handshake(error))==null); });
        run("suppressed graph cannot grow beyond budget", () -> { Throwable error=handshake(new EOFException()); for(int i=0;i<70;i++) error.addSuppressed(new IOException()); check(TransportFailureClassifier.classify(error)==null); });
        run("cycles rejected", () -> { Throwable cyclic=new IOException(){ @Override public synchronized Throwable getCause(){return this;} }; check(TransportFailureClassifier.classify(handshake(cyclic))==null); });
        run("inspection failure rejected", () -> { Throwable broken=new IOException(){ @Override public String getMessage(){throw new IllegalStateException();} }; check(TransportFailureClassifier.classify(handshake(broken))==null); });
        run("oversized message rejected", () -> { StringBuilder s=new StringBuilder("connection reset"); for(int i=0;i<5000;i++)s.append('x'); check(TransportFailureClassifier.classify(new SSLHandshakeException(s.toString()))==null); });
        run("exact state identity only", () -> {
            Object state=new Object(); Throwable original=handshake(new EOFException()); Throwable cause=original.getCause();
            TransportErrorScope.Frame frame=TransportErrorScope.begin();
            try { TransportErrorScope.arm(frame,original,state);
                check(TransportErrorScope.matching(state,null,new ErrorState(),ErrorState.class)==frame);
                check(TransportErrorScope.matching(new Object(),null,new ErrorState(),ErrorState.class)==null);
                check(original.getCause()==cause && original instanceof SSLHandshakeException);
            } finally { TransportErrorScope.end(frame); }
            check(TransportErrorScope.matching(state,null,new ErrorState(),ErrorState.class)==null);
        });
        run("only expected error state write suppressed", () -> {
            Object state=new Object(); TransportErrorScope.Frame frame=TransportErrorScope.begin();
            try { TransportErrorScope.arm(frame,handshake(new EOFException()),state);
                check(TransportErrorScope.matching(state,new Object(),new ErrorState(),ErrorState.class)==null);
                check(TransportErrorScope.matching(state,null,new NormalState(),ErrorState.class)==null);
                check(TransportErrorScope.matching(state,null,null,ErrorState.class)==null);
            } finally { TransportErrorScope.end(frame); }
        });
        run("nested genuine certificate error blocks inherited permission", () -> {
            Object state=new Object(); TransportErrorScope.Frame outer=TransportErrorScope.begin();
            try { TransportErrorScope.arm(outer,handshake(new EOFException()),state);
                TransportErrorScope.Frame inner=TransportErrorScope.begin();
                try { TransportErrorScope.arm(inner,handshake(new CertificateException()),state);
                    check(TransportErrorScope.matching(state,null,new ErrorState(),ErrorState.class)==null);
                } finally { TransportErrorScope.end(inner); }
                check(TransportErrorScope.matching(state,null,new ErrorState(),ErrorState.class)==outer);
            } finally { TransportErrorScope.end(outer); }
        });
        run("thread isolation", () -> {
            Object state=new Object(); TransportErrorScope.Frame frame=TransportErrorScope.begin(); final boolean[] isolated={false};
            try { TransportErrorScope.arm(frame,handshake(new EOFException()),state);
                Thread worker=new Thread(() -> isolated[0]=TransportErrorScope.matching(state,null,new ErrorState(),ErrorState.class)==null);
                worker.start(); worker.join(); check(isolated[0]);
            } finally { TransportErrorScope.end(frame); }
        });
        System.out.println("PASS: " + passed + " transport classifier/state-scope tests.");
    }
}
