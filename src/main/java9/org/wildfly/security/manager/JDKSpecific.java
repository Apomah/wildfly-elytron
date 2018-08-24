package org.wildfly.security.manager;

import java.lang.StackWalker;
import java.util.List;
import java.util.stream.Collectors;

final class JDKSpecific {
    public static Class<?> getCallerClass(int n){
        List<StackWalker.StackFrame> frames = StackWalker.getInstance().walk(s ->
                s.limit(n).collect(Collectors.toList())
        );
        return frames.get(frames.size() - 1).getClass();
    }

    public static Class<?> lookUpClass(){
        return StackWalker.StackFrame.class;
    }
}
