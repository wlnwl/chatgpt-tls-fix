package testsupport;

import java.util.ArrayList;
import java.util.List;

public final class Capture {
    public static final List<String> entries = new ArrayList<String>();
    public static final List<String> allEntries = new ArrayList<String>();
    private Capture() {}
    public static synchronized void add(String value) { entries.add(value); allEntries.add(value); }
    public static synchronized void clear() { entries.clear(); }
    public static synchronized String text() { return String.join("\n", entries); }
}
