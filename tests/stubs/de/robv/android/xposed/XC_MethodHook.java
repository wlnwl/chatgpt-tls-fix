package de.robv.android.xposed;

import java.lang.reflect.Member;
import java.util.HashMap;
import java.util.Map;
import testsupport.Capture;

public abstract class XC_MethodHook {
    public XC_MethodHook() {}
    public XC_MethodHook(int priority) {}
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {}
    protected void afterHookedMethod(MethodHookParam param) throws Throwable {}
    public final void testBefore(MethodHookParam param) throws Throwable { beforeHookedMethod(param); }
    public final void testAfter(MethodHookParam param) throws Throwable { afterHookedMethod(param); }
    public final class Unhook { public void unhook() {} }
    public static class MethodHookParam {
        public Object[] args;
        public Object thisObject;
        public Member method;
        private Object result;
        private Throwable throwable;
        private final Map<String,Object> extras = new HashMap<String,Object>();
        public Object getResult() { return result; }
        public void setResult(Object value) { result=value; throwable=null; Capture.add("MUTATE:result"); }
        public Throwable getThrowable() { return throwable; }
        public boolean hasThrowable() { return throwable != null; }
        public void setThrowable(Throwable value) { throwable=value; result=null; Capture.add("MUTATE:throwable"); }
        public Object getResultOrThrowable() throws Throwable { if (throwable != null) throw throwable; return result; }
        public void setObjectExtra(String key,Object value) { extras.put(key,value); }
        public Object getObjectExtra(String key) { return extras.get(key); }
        public void seed(Object value,Throwable failure) { result=value; throwable=failure; }
    }
}
