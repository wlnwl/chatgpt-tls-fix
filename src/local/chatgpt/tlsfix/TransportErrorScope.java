package local.chatgpt.tlsfix;

/** Per-call identity guard; nested calls always begin blocked, even inside an eligible call. */
final class TransportErrorScope {
    private static final ThreadLocal<Frame> CURRENT = new ThreadLocal<>();
    static final class Frame {
        private final Frame previous;
        private Object state;
        private String reason;
        private Throwable error;
        private Frame(Frame previous) { this.previous = previous; }
        String reason() { return reason; }
        Throwable error() { return error; }
    }
    static Frame begin() {
        Frame frame = new Frame(CURRENT.get());
        CURRENT.set(frame);
        return frame;
    }
    static void arm(Frame frame, Throwable error, Object state) {
        if (CURRENT.get() != frame || state == null) return;
        String reason = TransportFailureClassifier.classify(error);
        if (reason == null) return;
        frame.state = state;
        frame.reason = reason;
        frame.error = error;
    }
    static Frame matching(Object state, Object expected, Object update, Class<?> errorStateClass) {
        Frame frame = CURRENT.get();
        return frame != null && frame.reason != null && state == frame.state && expected == null
                && update != null && update.getClass() == errorStateClass ? frame : null;
    }
    static void end(Frame frame) {
        if (CURRENT.get() != frame || frame.previous == null) CURRENT.remove();
        else CURRENT.set(frame.previous);
    }
}
