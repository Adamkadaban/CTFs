package androidx.core.os;

import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcelable;
import android.util.Size;
import android.util.SizeF;
import java.io.Serializable;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Typography;
/* compiled from: Bundle.kt */
@Metadata(d1 = {"\u0000\u001c\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0010\u0000\n\u0002\b\u0002\u001a;\u0010\u0000\u001a\u00020\u00012.\u0010\u0002\u001a\u0018\u0012\u0014\b\u0001\u0012\u0010\u0012\u0004\u0012\u00020\u0005\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u00040\u0003\"\u0010\u0012\u0004\u0012\u00020\u0005\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u0004¢\u0006\u0002\u0010\u0007¨\u0006\b"}, d2 = {"bundleOf", "Landroid/os/Bundle;", "pairs", "", "Lkotlin/Pair;", "", "", "([Lkotlin/Pair;)Landroid/os/Bundle;", "core-ktx_release"}, k = 2, mv = {1, 5, 1}, xi = 48)
/* loaded from: classes.dex */
public final class BundleKt {
    public static final Bundle bundleOf(Pair<String, ? extends Object>... pairs) {
        Intrinsics.checkNotNullParameter(pairs, "pairs");
        Bundle $this$bundleOf_u24lambda_u2d0 = new Bundle(pairs.length);
        int length = pairs.length;
        int i = 0;
        while (i < length) {
            Pair<String, ? extends Object> pair = pairs[i];
            i++;
            String key = pair.component1();
            Object value = pair.component2();
            if (value == null) {
                $this$bundleOf_u24lambda_u2d0.putString(key, null);
            } else if (value instanceof Boolean) {
                $this$bundleOf_u24lambda_u2d0.putBoolean(key, ((Boolean) value).booleanValue());
            } else if (value instanceof Byte) {
                $this$bundleOf_u24lambda_u2d0.putByte(key, ((Number) value).byteValue());
            } else if (value instanceof Character) {
                $this$bundleOf_u24lambda_u2d0.putChar(key, ((Character) value).charValue());
            } else if (value instanceof Double) {
                $this$bundleOf_u24lambda_u2d0.putDouble(key, ((Number) value).doubleValue());
            } else if (value instanceof Float) {
                $this$bundleOf_u24lambda_u2d0.putFloat(key, ((Number) value).floatValue());
            } else if (value instanceof Integer) {
                $this$bundleOf_u24lambda_u2d0.putInt(key, ((Number) value).intValue());
            } else if (value instanceof Long) {
                $this$bundleOf_u24lambda_u2d0.putLong(key, ((Number) value).longValue());
            } else if (value instanceof Short) {
                $this$bundleOf_u24lambda_u2d0.putShort(key, ((Number) value).shortValue());
            } else if (value instanceof Bundle) {
                $this$bundleOf_u24lambda_u2d0.putBundle(key, (Bundle) value);
            } else if (value instanceof CharSequence) {
                $this$bundleOf_u24lambda_u2d0.putCharSequence(key, (CharSequence) value);
            } else if (value instanceof Parcelable) {
                $this$bundleOf_u24lambda_u2d0.putParcelable(key, (Parcelable) value);
            } else if (value instanceof boolean[]) {
                $this$bundleOf_u24lambda_u2d0.putBooleanArray(key, (boolean[]) value);
            } else if (value instanceof byte[]) {
                $this$bundleOf_u24lambda_u2d0.putByteArray(key, (byte[]) value);
            } else if (value instanceof char[]) {
                $this$bundleOf_u24lambda_u2d0.putCharArray(key, (char[]) value);
            } else if (value instanceof double[]) {
                $this$bundleOf_u24lambda_u2d0.putDoubleArray(key, (double[]) value);
            } else if (value instanceof float[]) {
                $this$bundleOf_u24lambda_u2d0.putFloatArray(key, (float[]) value);
            } else if (value instanceof int[]) {
                $this$bundleOf_u24lambda_u2d0.putIntArray(key, (int[]) value);
            } else if (value instanceof long[]) {
                $this$bundleOf_u24lambda_u2d0.putLongArray(key, (long[]) value);
            } else if (value instanceof short[]) {
                $this$bundleOf_u24lambda_u2d0.putShortArray(key, (short[]) value);
            } else if (value instanceof Object[]) {
                Class componentType = value.getClass().getComponentType();
                Intrinsics.checkNotNull(componentType);
                if (Parcelable.class.isAssignableFrom(componentType)) {
                    if (value == null) {
                        throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<android.os.Parcelable>");
                    }
                    $this$bundleOf_u24lambda_u2d0.putParcelableArray(key, (Parcelable[]) value);
                } else if (String.class.isAssignableFrom(componentType)) {
                    if (value == null) {
                        throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<kotlin.String>");
                    }
                    $this$bundleOf_u24lambda_u2d0.putStringArray(key, (String[]) value);
                } else if (CharSequence.class.isAssignableFrom(componentType)) {
                    if (value == null) {
                        throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<kotlin.CharSequence>");
                    }
                    $this$bundleOf_u24lambda_u2d0.putCharSequenceArray(key, (CharSequence[]) value);
                } else if (Serializable.class.isAssignableFrom(componentType)) {
                    $this$bundleOf_u24lambda_u2d0.putSerializable(key, (Serializable) value);
                } else {
                    String valueType = componentType.getCanonicalName();
                    throw new IllegalArgumentException("Illegal value array type " + ((Object) valueType) + " for key \"" + key + Typography.quote);
                }
            } else if (value instanceof Serializable) {
                $this$bundleOf_u24lambda_u2d0.putSerializable(key, (Serializable) value);
            } else if (Build.VERSION.SDK_INT >= 18 && (value instanceof IBinder)) {
                $this$bundleOf_u24lambda_u2d0.putBinder(key, (IBinder) value);
            } else if (Build.VERSION.SDK_INT >= 21 && (value instanceof Size)) {
                $this$bundleOf_u24lambda_u2d0.putSize(key, (Size) value);
            } else if (Build.VERSION.SDK_INT >= 21 && (value instanceof SizeF)) {
                $this$bundleOf_u24lambda_u2d0.putSizeF(key, (SizeF) value);
            } else {
                String valueType2 = value.getClass().getCanonicalName();
                throw new IllegalArgumentException("Illegal value type " + ((Object) valueType2) + " for key \"" + key + Typography.quote);
            }
        }
        return $this$bundleOf_u24lambda_u2d0;
    }
}
