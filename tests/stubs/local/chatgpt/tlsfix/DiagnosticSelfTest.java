package local.chatgpt.tlsfix;
public final class DiagnosticSelfTest {
    public static boolean preserveConscrypt;
    public static boolean preserveConscryptForSelfTest() { return preserveConscrypt; }
    public static void install(ClassLoader loader) {}
    public static void maybeRun(ClassLoader loader) {}
    public static void installTrigger(ClassLoader loader) {}
}
