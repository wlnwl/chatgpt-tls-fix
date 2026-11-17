package org.chromium.net;
import java.security.cert.X509Certificate;
import java.util.List;
public class AndroidCertVerifyResult {
    private final int status;
    public final boolean knownRoot;
    public final List<X509Certificate> chain;
    public AndroidCertVerifyResult(int status,boolean knownRoot,List<X509Certificate> chain) {
        this.status=status; this.knownRoot=knownRoot; this.chain=chain;
    }
    public int getStatus() { return status; }
}
