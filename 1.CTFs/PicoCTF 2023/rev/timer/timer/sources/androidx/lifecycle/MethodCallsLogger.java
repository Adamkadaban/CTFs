package androidx.lifecycle;

import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public class MethodCallsLogger {
    private Map<String, Integer> mCalledMethods = new HashMap();

    public boolean approveCall(String name, int type) {
        Integer nullableMask = this.mCalledMethods.get(name);
        int mask = nullableMask != null ? nullableMask.intValue() : 0;
        boolean wasCalled = (mask & type) != 0;
        this.mCalledMethods.put(name, Integer.valueOf(mask | type));
        return !wasCalled;
    }
}
