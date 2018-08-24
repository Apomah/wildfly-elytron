package org.wildfly.security.manager;

import sun.reflect.Reflection;

final class JDKSpecific {
    public static Class<?> getCallerClass(int n){
        return Reflection.getCallerClass(n);
    }

    public static Class<?> lookUpClass(){
        return Reflection.class;
    }
}
