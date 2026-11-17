package local.chatgpt.tlsfix;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageInfo;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.concurrent.atomic.AtomicBoolean;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/** Correct only the supported client's transport-error UI classification; preserve request failure. */
final class TransportErrorGuard {
    private static final AtomicBoolean ATTEMPTED = new AtomicBoolean();
    private static final String FRAME = "local.chatgpt.tlsfix.transport.frame";

    static void install(final ClassLoader loader) {
        try {
            XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class, new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    if (!ATTEMPTED.compareAndSet(false, true)) return;
                    try {
                        Context context = (Context) p.args[0];
                        if (!"com.openai.chatgpt".equals(context.getPackageName())) return;
                        PackageInfo info = context.getPackageManager().getPackageInfo("com.openai.chatgpt", 0);
                        if (info.getLongVersionCode() != 2630718L || !"1.2026.307".equals(info.versionName)) {
                            skipped("unsupported_app_version", null);
                            return;
                        }
                        installSupported(loader);
                    } catch (Throwable error) { skipped("version_or_shape_check_failed", error); }
                }
            });
        } catch (Throwable error) { skipped("attach_hook_unavailable", error); }
    }

    private static void installSupported(ClassLoader loader) throws Throwable {
        Class<?> mapperClass = Class.forName("fzi0", false, loader);
        Class<?> serviceClass = Class.forName("oyi0", false, loader);
        Class<?> stateClass = Class.forName("gp21", false, loader);
        final Class<?> errorStateClass = Class.forName("lyi0", false, loader);
        Class<?> requestClass = Class.forName("el71", false, loader);
        Class<?> continuationClass = Class.forName("o3s", false, loader);
        final Field service = mapperClass.getDeclaredField("a");
        final Field state = serviceClass.getDeclaredField("c");
        Method mapper = mapperClass.getDeclaredMethod("a", Throwable.class, requestClass, continuationClass);
        Method setter = stateClass.getDeclaredMethod("n", Object.class, Object.class);
        if (service.getType() != serviceClass || state.getType() != stateClass
                || mapper.getReturnType() != Object.class || setter.getReturnType() != boolean.class
                || Modifier.isStatic(mapper.getModifiers()) || Modifier.isStatic(setter.getModifiers())
                || !Modifier.isFinal(mapperClass.getModifiers()) || !Modifier.isFinal(serviceClass.getModifiers())
                || !Modifier.isFinal(service.getModifiers()) || !Modifier.isFinal(state.getModifiers())) {
            throw new IllegalStateException("Unsupported mapper/state shape");
        }
        service.setAccessible(true);
        state.setAccessible(true);
        mapper.setAccessible(true);
        setter.setAccessible(true);
        // The setter hook is inert until a correctly scoped mapper call arms the thread-local frame.
        final XC_MethodHook.Unhook setterHook = XposedBridge.hookMethod(setter, new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam p) {
                try {
                    if (p.args == null || p.args.length != 2) return;
                    TransportErrorScope.Frame frame = TransportErrorScope.matching(p.thisObject, p.args[0], p.args[1], errorStateClass);
                    if (frame == null) return;
                    // n(expected,new) is a boolean state update. false means no update, not request success.
                    // The verified fzi0.a call site ignores this return and continues its ordinary error mapper.
                    p.setResult(Boolean.FALSE);
                    DiagnosticLog.emit("transport_error_state_suppressed", "network_error_mapper", null,
                            frame.reason(), frame.error(), null, null);
                } catch (Throwable error) { skipped("state_callback_failed", error); }
            }
        });
        try {
            XposedBridge.hookMethod(mapper, new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam p) {
                    TransportErrorScope.Frame frame = TransportErrorScope.begin();
                    p.setObjectExtra(FRAME, frame);
                    try {
                        if (p.args == null || p.args.length != 3 || !(p.args[0] instanceof Throwable)) return;
                        Object targetService = service.get(p.thisObject);
                        if (targetService == null) return;
                        Object targetState = state.get(targetService);
                        Throwable original = (Throwable) p.args[0];
                        TransportErrorScope.arm(frame, original, targetState);
                        if (frame.reason() == null) skipped("not_transport_only", original);
                    } catch (Throwable error) { skipped("mapper_callback_failed", error); }
                }
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    Object frame = p.getObjectExtra(FRAME);
                    if (frame instanceof TransportErrorScope.Frame) TransportErrorScope.end((TransportErrorScope.Frame) frame);
                }
            });
        } catch (Throwable error) {
            setterHook.unhook();
            throw error;
        }
        DiagnosticLog.emit("guard_registered", "network_error_mapper", null,
                "app_1.2026.307_transport_only", null, null, null);
    }
    private static void skipped(String outcome, Throwable error) {
        DiagnosticLog.emit("guard_skipped", "network_error_mapper", null, outcome, error, null, null);
    }
}
