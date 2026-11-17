package de.robv.android.xposed;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

public final class XposedHelpers {
    public static Class<?> findClassIfExists(String name,ClassLoader loader) {
        try { return Class.forName(name,false,loader); } catch (Throwable error) { return null; }
    }
    public static Class<?> findClass(String name,ClassLoader loader) {
        Class<?> type=findClassIfExists(name,loader);
        if (type==null) throw new IllegalArgumentException(name);
        return type;
    }
    public static Object callMethod(Object object,String name,Object... args) {
        try {
            for (Method method:object.getClass().getMethods()) if(method.getName().equals(name) && method.getParameterTypes().length==args.length) {
                method.setAccessible(true); return method.invoke(object,args);
            }
            throw new NoSuchMethodException(name);
        } catch (Exception error) { throw new IllegalStateException(error); }
    }
    public static Object newInstance(Class<?> type,Object... args) {
        try {
            for (Constructor<?> ctor:type.getDeclaredConstructors()) if(ctor.getParameterTypes().length==args.length) {
                ctor.setAccessible(true); return ctor.newInstance(args);
            }
            throw new NoSuchMethodException(type.getName());
        } catch (Exception error) { throw new IllegalStateException(error); }
    }
}
