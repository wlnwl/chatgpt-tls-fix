package de.robv.android.xposed;

import java.lang.reflect.Constructor;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import testsupport.Capture;

public final class XposedBridge {
    public static final Map<String,List<XC_MethodHook>> hooks = new LinkedHashMap<String,List<XC_MethodHook>>();
    public static boolean failWrites;
    public static void log(String message) {
        if (failWrites) throw new IllegalStateException("test Xposed log sink failure");
        Capture.add("LOG:Xposed:"+message);
    }
    public static void log(Throwable failure) { log(failure.getClass().getName()); }
    public static Set<XC_MethodHook.Unhook> hookAllMethods(Class<?> type,String name,XC_MethodHook hook) {
        Set<XC_MethodHook.Unhook> result = new HashSet<XC_MethodHook.Unhook>();
        for (Method method:type.getDeclaredMethods()) if (method.getName().equals(name)) {
            register(type.getName()+"#"+name,hook);
            result.add(hook.new Unhook());
        }
        return result;
    }
    public static Set<XC_MethodHook.Unhook> hookAllConstructors(Class<?> type,XC_MethodHook hook) {
        Set<XC_MethodHook.Unhook> result = new HashSet<XC_MethodHook.Unhook>();
        register(type.getName()+"#<init>",hook);
        for (Constructor<?> ctor:type.getDeclaredConstructors()) result.add(hook.new Unhook());
        return result;
    }
    public static XC_MethodHook.Unhook hookMethod(Member member,XC_MethodHook hook) {
        register(member.getDeclaringClass().getName()+"#"+member.getName(),hook);
        return hook.new Unhook();
    }
    private static void register(String key,XC_MethodHook hook) {
        List<XC_MethodHook> entries=hooks.get(key);
        if (entries==null) { entries=new ArrayList<XC_MethodHook>(); hooks.put(key,entries); }
        if (!entries.contains(hook)) entries.add(hook);
    }
}
