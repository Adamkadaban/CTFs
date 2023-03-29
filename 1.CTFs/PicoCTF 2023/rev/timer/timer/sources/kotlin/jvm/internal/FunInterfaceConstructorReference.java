package kotlin.jvm.internal;

import java.io.Serializable;
import kotlin.reflect.KFunction;
/* loaded from: classes.dex */
public class FunInterfaceConstructorReference extends FunctionReference implements Serializable {
    private final Class funInterface;

    public FunInterfaceConstructorReference(Class funInterface) {
        super(1);
        this.funInterface = funInterface;
    }

    @Override // kotlin.jvm.internal.FunctionReference
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof FunInterfaceConstructorReference) {
            FunInterfaceConstructorReference other = (FunInterfaceConstructorReference) o;
            return this.funInterface.equals(other.funInterface);
        }
        return false;
    }

    @Override // kotlin.jvm.internal.FunctionReference
    public int hashCode() {
        return this.funInterface.hashCode();
    }

    @Override // kotlin.jvm.internal.FunctionReference
    public String toString() {
        return "fun interface " + this.funInterface.getName();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // kotlin.jvm.internal.FunctionReference, kotlin.jvm.internal.CallableReference
    public KFunction getReflected() {
        throw new UnsupportedOperationException("Functional interface constructor does not support reflection");
    }
}
