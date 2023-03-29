package kotlin.jvm.internal;

import kotlin.reflect.KClass;
import kotlin.reflect.KDeclarationContainer;
/* loaded from: classes.dex */
public class MutablePropertyReference1Impl extends MutablePropertyReference1 {
    public MutablePropertyReference1Impl(KDeclarationContainer owner, String name, String signature) {
        super(NO_RECEIVER, ((ClassBasedDeclarationContainer) owner).getJClass(), name, signature, !(owner instanceof KClass) ? 1 : 0);
    }

    public MutablePropertyReference1Impl(Class owner, String name, String signature, int flags) {
        super(NO_RECEIVER, owner, name, signature, flags);
    }

    public MutablePropertyReference1Impl(Object receiver, Class owner, String name, String signature, int flags) {
        super(receiver, owner, name, signature, flags);
    }

    @Override // kotlin.reflect.KProperty1
    public Object get(Object receiver) {
        return getGetter().call(receiver);
    }

    @Override // kotlin.reflect.KMutableProperty1
    public void set(Object receiver, Object value) {
        getSetter().call(receiver, value);
    }
}
