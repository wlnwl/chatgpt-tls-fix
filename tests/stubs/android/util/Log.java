package android.util;

import testsupport.Capture;

public final class Log {
    public static final int DEBUG=3, INFO=4, WARN=5, ERROR=6;
    public static boolean failWrites;
    private static int write(String tag, String message) {
        if (failWrites) throw new IllegalStateException("test log sink failure");
        Capture.add("LOG:"+tag+":"+message);
        return message.length();
    }
    public static int d(String tag,String message) { return write(tag,message); }
    public static int i(String tag,String message) { return write(tag,message); }
    public static int w(String tag,String message) { return write(tag,message); }
    public static int e(String tag,String message) { return write(tag,message); }
    public static int println(int priority,String tag,String message) { return write(tag,message); }
}
