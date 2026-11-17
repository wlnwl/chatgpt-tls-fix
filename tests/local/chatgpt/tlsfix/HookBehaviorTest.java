package local.chatgpt.tlsfix;

import android.util.Log;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodHook.MethodHookParam;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLHandshakeException;
import org.chromium.net.AndroidCertVerifyResult;
import testsupport.Capture;

/** Tests actual callbacks with host-only Xposed doubles, without network or Android dependencies. */
public final class HookBehaviorTest {
    private static final String CONSCRYPT="com.android.org.conscrypt.TrustManagerImpl#verifyChain";
    private static final String CRONET="org.chromium.net.X509Util#verifyServerCertificates";
    private static final String HOST="diagnostic.chatgpt.com";
    private static byte[] der;
    private static List<X509Certificate> chain;
    private static int passed;
    private interface Test { void run() throws Throwable; }

    public static void main(String[] args) throws Throwable {
        der=Files.readAllBytes(Paths.get(args[0]));
        chain=Collections.singletonList((X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der)));
        run("scope boundary accepts only configured hostname suffixes",()-> {
            check(TlsHook.allowedHost("CHATGPT.COM"),"case-insensitive exact match");
            check(TlsHook.allowedHost("android.chat.openai.com"),"nested subdomain");
            check(!TlsHook.allowedHost("chatgpt.com.attacker.invalid"),"suffix confusion");
            check(!TlsHook.allowedHost("notchatgpt.com"),"missing label boundary");
            check(!TlsHook.allowedHost(null),"null host");
        });
        run("unrelated process installs no hook",()-> {
            new TlsHook().handleLoadPackage(loadPackage("unrelated.application"));
            check(XposedBridge.hooks.isEmpty(),"hooks leaked outside target package");
        });
        new TlsHook().handleLoadPackage(loadPackage("com.openai.chatgpt"));
        check(XposedBridge.hooks.containsKey(CONSCRYPT),"Conscrypt hook registered");
        check(XposedBridge.hooks.containsKey(CRONET),"Cronet hook registered");

        run("Conscrypt logs original failure before replacing it",()-> {
            CertificateException failure=new CertificateException("Trust anchor for certification path not found.");
            MethodHookParam p=invoke(CONSCRYPT,conscryptArgs(HOST,chain),null,failure);
            check(p.getResult()==chain && !p.hasThrowable(),"existing compatibility replacement missing");
            requireEvent("verification_failed"); requireEvent("verification_bypassed");
            int logged=indexContaining("verification_failed");
            int changed=indexContaining("MUTATE:result");
            check(logged>=0 && changed>logged,"original failure must be logged before replacement");
        });
        run("Conscrypt accepted result remains identical",()-> {
            List<X509Certificate> result=new ArrayList<X509Certificate>(chain);
            MethodHookParam p=invoke(CONSCRYPT,conscryptArgs(HOST,chain),result,null);
            check(p.getResult()==result && !p.hasThrowable(),"successful validation was changed");
            check(!Capture.text().contains("MUTATE:"),"accepted result mutated");
            requireEvent("verification_accepted");
        });
        run("Conscrypt out-of-scope certificate failure preserved",()-> {
            Throwable failure=new CertificateException("untrusted test chain");
            MethodHookParam p=invoke(CONSCRYPT,conscryptArgs("diagnostic.invalid",chain),null,failure);
            check(p.getThrowable()==failure,"scope escaped");
            check(!Capture.text().contains("verification_bypassed"),"misleading bypass event");
        });
        run("Conscrypt empty chain cannot be reported as repaired",()-> {
            Throwable failure=new CertificateException("empty chain");
            MethodHookParam p=invoke(CONSCRYPT,conscryptArgs(HOST,Collections.emptyList()),null,failure);
            check(p.getThrowable()==failure,"empty-chain failure changed");
            requireEvent("skipped");
            check(!Capture.text().contains("verification_bypassed"),"empty chain bypass reported");
        });
        run("Conscrypt non-certificate exception preserved",()-> {
            Throwable failure=new IllegalStateException("unexpected provider issue");
            MethodHookParam p=invoke(CONSCRYPT,conscryptArgs(HOST,chain),null,failure);
            check(p.getThrowable()==failure,"non-certificate error changed");
        });
        run("invalid callback shape remains non-invasive",()-> {
            Throwable failure=new CertificateException("test");
            MethodHookParam p=invoke(CONSCRYPT,new Object[]{null},null,failure);
            check(p.getThrowable()==failure,"bad argument list changed");
        });
        run("Cronet nonzero verification status recorded before replacement",()-> {
            AndroidCertVerifyResult original=new AndroidCertVerifyResult(-2,false,chain);
            MethodHookParam p=invoke(CRONET,cronetArgs(HOST,new byte[][]{der}),original,null);
            check(p.getResult()!=original,"failed status unchanged");
            check(((AndroidCertVerifyResult)p.getResult()).getStatus()==0,"replacement not successful");
            requireEvent("verification_failed"); requireEvent("verification_bypassed");
            check(indexContaining("verification_failed")<indexContaining("MUTATE:result"),"failure log ordering");
            check(Capture.text().contains("-2"),"original Cronet status missing");
        });
        run("Cronet success result remains identical",()-> {
            AndroidCertVerifyResult original=new AndroidCertVerifyResult(0,true,chain);
            MethodHookParam p=invoke(CRONET,cronetArgs(HOST,new byte[][]{der}),original,null);
            check(p.getResult()==original,"success changed");
            requireEvent("verification_accepted");
        });
        run("Cronet original exception remains identical",()-> {
            Throwable failure=new CertificateException("provider threw");
            MethodHookParam p=invoke(CRONET,cronetArgs(HOST,new byte[][]{der}),null,failure);
            check(p.getThrowable()==failure,"original throwable swallowed");
            requireEvent("verification_failed");
            check(!Capture.text().contains("verification_bypassed"),"false bypass event");
        });
        run("Cronet null result remains null",()-> {
            MethodHookParam p=invoke(CRONET,cronetArgs(HOST,new byte[][]{der}),null,null);
            check(p.getResult()==null && !p.hasThrowable(),"null result changed");
            requireEvent("skipped");
        });
        run("Cronet malformed DER preserves original failed result",()-> {
            AndroidCertVerifyResult original=new AndroidCertVerifyResult(-1,false,chain);
            MethodHookParam p=invoke(CRONET,cronetArgs(HOST,new byte[][]{{1,2,3,4}}),original,null);
            check(p.getResult()==original && !p.hasThrowable(),"parse error replaced caller result");
            requireEvent("hook_error");
            check(!Capture.text().contains("verification_bypassed"),"false malformed-cert bypass");
        });
        run("Cronet empty chain preserves original failed result",()-> {
            AndroidCertVerifyResult original=new AndroidCertVerifyResult(-1,false,chain);
            MethodHookParam p=invoke(CRONET,cronetArgs(HOST,new byte[0][]),original,null);
            check(p.getResult()==original && !p.hasThrowable(),"empty chain changed");
            requireEvent("skipped");
        });
        run("Cronet non-target hostname does not bypass",()-> {
            AndroidCertVerifyResult original=new AndroidCertVerifyResult(-2,false,chain);
            MethodHookParam p=invoke(CRONET,cronetArgs("chatgpt.com.attacker.invalid",new byte[][]{der}),original,null);
            check(p.getResult()==original,"non-target hostname bypassed");
        });
        run("reflection failure preserves original result",()-> {
            Object original=new Object();
            MethodHookParam p=invoke(CRONET,cronetArgs(HOST,new byte[][]{der}),original,null);
            check(p.getResult()==original && !p.hasThrowable(),"reflection exception leaked to caller");
            requireEvent("hook_error");
        });
        run("saturated success logging cannot hide later verification failure",()-> {
            for(int i=0;i<80;i++) invoke(CRONET,cronetArgs(HOST,new byte[][]{der}),new AndroidCertVerifyResult(0,true,chain),null);
            MethodHookParam p=invoke(CONSCRYPT,conscryptArgs(HOST,chain),null,new CertificateException("rate-limit test"));
            check(p.getResult()==chain,"result changed by rate limiting");
            requireEvent("verification_failed"); requireEvent("verification_bypassed");
        });
        run("exception messages cannot leak credentials to logs",()-> {
            invoke(CONSCRYPT,conscryptArgs(HOST,chain),null,new CertificateException("https://private.invalid/?token=SECRET_AUTH_TOKEN\nsecond-line"));
            check(!Capture.text().contains("SECRET_AUTH_TOKEN"),"raw exception secret leaked");
            check(!Capture.text().contains("BEGIN CERTIFICATE"),"full cert dump unexpectedly logged");
            requireEvent("verification_failed");
        });
        run("both failing log sinks do not break successful verification",()-> {
            Log.failWrites=true; XposedBridge.failWrites=true;
            try {
                Object original=new AndroidCertVerifyResult(0,true,chain);
                MethodHookParam p=invoke(CRONET,cronetArgs(HOST,new byte[][]{der}),original,null);
                check(p.getResult()==original && !p.hasThrowable(),"logger altered original result");
            } finally { Log.failWrites=false; XposedBridge.failWrites=false; }
        });
        run("both failing log sinks do not prevent existing failure handling",()-> {
            Log.failWrites=true; XposedBridge.failWrites=true;
            try {
                MethodHookParam p=invoke(CONSCRYPT,conscryptArgs(HOST,chain),null,new CertificateException("test"));
                check(p.getResult()==chain && !p.hasThrowable(),"logger interrupted compatibility behavior");
            } finally { Log.failWrites=false; XposedBridge.failWrites=false; }
        });
        run("one broken sink still leaves an observable failure",()-> {
            Log.failWrites=true;
            try { invoke(CONSCRYPT,conscryptArgs(HOST,chain),null,new CertificateException("test")); }
            finally { Log.failWrites=false; }
            requireEvent("verification_failed");
        });
        run("controlled self-test events never increment live failure counts",()-> {
            Map<String,Long> before=DiagnosticLog.countersSnapshot();
            long live=value(before,"live.verification_failed");
            long self=value(before,"self_test.verification_failed");
            DiagnosticLog.beginSelfTest();
            try { invoke(CONSCRYPT,conscryptArgs(HOST,chain),null,new CertificateException("controlled fixture")); }
            finally { DiagnosticLog.endSelfTest(); }
            Map<String,Long> after=DiagnosticLog.countersSnapshot();
            check(value(after,"live.verification_failed")==live,"self test contaminated live counter");
            check(value(after,"self_test.verification_failed")==self+1,"self-test counter missing");
            check(Capture.text().contains("self_test"),"self-test source not emitted");
        });
        run("controlled original baseline is observed without bypass",()-> {
            DiagnosticSelfTest.preserveConscrypt=true;
            DiagnosticLog.beginSelfTest();
            Throwable original=new CertificateException("controlled baseline");
            try {
                MethodHookParam p=invoke(CONSCRYPT,conscryptArgs(HOST,chain),null,original);
                check(p.getThrowable()==original,"baseline was bypassed by nested hook");
                requireEvent("verification_failed");
                check(!Capture.text().contains("verification_bypassed"),"baseline reported as bypassed");
            } finally { DiagnosticSelfTest.preserveConscrypt=false; DiagnosticLog.endSelfTest(); }
        });
        run("handshake observation does not mutate exceptions",()-> {
            String key="javax.net.ssl.SSLHandshakeException#<init>";
            check(XposedBridge.hooks.containsKey(key),"handshake observation hook missing");
            SSLHandshakeException original=new SSLHandshakeException("Remote host terminated the handshake");
            MethodHookParam p=new MethodHookParam(); p.args=new Object[]{"test"}; p.thisObject=original;
            Capture.clear();
            for(XC_MethodHook hook:XposedBridge.hooks.get(key)) hook.testAfter(p);
            check(!Capture.text().contains("MUTATE:"),"constructor observation mutated result");
            check(!p.hasThrowable(),"constructor observation threw");
        });
        if(args.length>1) {
            List<String> json=new ArrayList<String>();
            for(String entry:Capture.allEntries) {
                int start=entry.indexOf("[ChatGPT-TLS] {");
                if(start>=0) json.add(entry.substring(start+"[ChatGPT-TLS] ".length()));
            }
            Files.write(Paths.get(args[1]),json,StandardCharsets.UTF_8);
        }
        System.out.println("PASS: "+passed+" host behavior tests. These are callback tests, not a device/network success claim.");
    }
    private static XC_LoadPackage.LoadPackageParam loadPackage(String pkg) {
        XC_LoadPackage.LoadPackageParam p=new XC_LoadPackage.LoadPackageParam();
        p.packageName=pkg; p.processName=pkg; p.classLoader=HookBehaviorTest.class.getClassLoader(); return p;
    }
    private static Object[] conscryptArgs(String host,List<?> certificates) {
        return new Object[]{certificates,Collections.emptyList(),host,false,null,null};
    }
    private static Object[] cronetArgs(String host,byte[][] certificates) { return new Object[]{certificates,"RSA",host}; }
    private static MethodHookParam invoke(String key,Object[] args,Object result,Throwable failure) throws Throwable {
        List<XC_MethodHook> hooks=XposedBridge.hooks.get(key);
        check(hooks!=null && !hooks.isEmpty(),"hook absent: "+key);
        MethodHookParam p=new MethodHookParam(); p.args=args;
        Capture.clear();
        for(XC_MethodHook hook:hooks) hook.testBefore(p);
        p.seed(result,failure);
        for(int i=hooks.size()-1;i>=0;i--) hooks.get(i).testAfter(p);
        return p;
    }
    private static int indexContaining(String text) {
        for(int i=0;i<Capture.entries.size();i++) if(Capture.entries.get(i).contains(text)) return i;
        return -1;
    }
    private static long value(Map<String,Long> counts,String key) { Long v=counts.get(key); return v==null?0L:v; }
    private static void requireEvent(String event) { check(Capture.text().contains(event),"event missing: "+event+"\n"+Capture.text()); }
    private static void check(boolean passed,String message) { if(!passed) throw new AssertionError(message); }
    private static void run(String name,Test test) throws Throwable {
        try { test.run(); passed++; System.out.println("PASS "+name); }
        catch(Throwable failure) { System.err.println("FAIL "+name); throw failure; }
    }
}
