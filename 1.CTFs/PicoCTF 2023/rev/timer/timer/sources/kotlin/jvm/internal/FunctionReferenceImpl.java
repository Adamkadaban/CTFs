package kotlin.jvm.internal;

import kotlin.reflect.KClass;
import kotlin.reflect.KDeclarationContainer;
/* loaded from: classes.dex */
public class FunctionReferenceImpl extends FunctionReference {
    public FunctionReferenceImpl(int arity, KDeclarationContainer owner, String name, String signature) {
        super(arity, NO_RECEIVER, ((ClassBasedDeclarationContainer) owner).getJClass(), name, signature, !(owner instanceof KClass) ? 1 : 0);
    }

    public FunctionReferenceImpl(int arity, Class owner, String name, String signature, int flags) {
        super(arity, NO_RECEIVER, owner, name, signature, flags);
    }

    public FunctionReferenceImpl(int arity, Object receiver, Class owner, String name, String signature, int flags) {
        super(arity, receiver, owner, name, signature, flags);
    }
}
