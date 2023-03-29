package kotlin.jvm.internal;

import java.io.Serializable;
import kotlin.reflect.KDeclarationContainer;
/* loaded from: classes.dex */
public class AdaptedFunctionReference implements FunctionBase, Serializable {
    private final int arity;
    private final int flags;
    private final boolean isTopLevel;
    private final String name;
    private final Class owner;
    protected final Object receiver;
    private final String signature;

    public AdaptedFunctionReference(int arity, Class owner, String name, String signature, int flags) {
        this(arity, CallableReference.NO_RECEIVER, owner, name, signature, flags);
    }

    public AdaptedFunctionReference(int arity, Object receiver, Class owner, String name, String signature, int flags) {
        this.receiver = receiver;
        this.owner = owner;
        this.name = name;
        this.signature = signature;
        this.isTopLevel = (flags & 1) == 1;
        this.arity = arity;
        this.flags = flags >> 1;
    }

    @Override // kotlin.jvm.internal.FunctionBase
    public int getArity() {
        return this.arity;
    }

    public KDeclarationContainer getOwner() {
        Class cls = this.owner;
        if (cls == null) {
            return null;
        }
        return this.isTopLevel ? Reflection.getOrCreateKotlinPackage(cls) : Reflection.getOrCreateKotlinClass(cls);
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof AdaptedFunctionReference) {
            AdaptedFunctionReference other = (AdaptedFunctionReference) o;
            return this.isTopLevel == other.isTopLevel && this.arity == other.arity && this.flags == other.flags && Intrinsics.areEqual(this.receiver, other.receiver) && Intrinsics.areEqual(this.owner, other.owner) && this.name.equals(other.name) && this.signature.equals(other.signature);
        }
        return false;
    }

    public int hashCode() {
        Object obj = this.receiver;
        int result = obj != null ? obj.hashCode() : 0;
        int i = result * 31;
        Class cls = this.owner;
        int result2 = i + (cls != null ? cls.hashCode() : 0);
        return (((((((((result2 * 31) + this.name.hashCode()) * 31) + this.signature.hashCode()) * 31) + (this.isTopLevel ? 1231 : 1237)) * 31) + this.arity) * 31) + this.flags;
    }

    public String toString() {
        return Reflection.renderLambdaToString(this);
    }
}
