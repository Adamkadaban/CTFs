package kotlin.collections;

import java.util.RandomAccess;
import kotlin.Metadata;
/* compiled from: _ArraysJvm.kt */
@Metadata(d1 = {"\u0000'\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\b*\u0001\u0000\b\n\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u00012\u00060\u0003j\u0002`\u0004J\u0011\u0010\t\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\u0002H\u0096\u0002J\u0016\u0010\f\u001a\u00020\u00022\u0006\u0010\r\u001a\u00020\u0006H\u0096\u0002¢\u0006\u0002\u0010\u000eJ\u0010\u0010\u000f\u001a\u00020\u00062\u0006\u0010\u000b\u001a\u00020\u0002H\u0016J\b\u0010\u0010\u001a\u00020\nH\u0016J\u0010\u0010\u0011\u001a\u00020\u00062\u0006\u0010\u000b\u001a\u00020\u0002H\u0016R\u0014\u0010\u0005\u001a\u00020\u00068VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0007\u0010\b¨\u0006\u0012"}, d2 = {"kotlin/collections/ArraysKt___ArraysJvmKt$asList$5", "Lkotlin/collections/AbstractList;", "", "Ljava/util/RandomAccess;", "Lkotlin/collections/RandomAccess;", "size", "", "getSize", "()I", "contains", "", "element", "get", "index", "(I)Ljava/lang/Float;", "indexOf", "isEmpty", "lastIndexOf", "kotlin-stdlib"}, k = 1, mv = {1, 6, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ArraysKt___ArraysJvmKt$asList$5 extends AbstractList<Float> implements RandomAccess {
    final /* synthetic */ float[] $this_asList;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ArraysKt___ArraysJvmKt$asList$5(float[] $receiver) {
        this.$this_asList = $receiver;
    }

    @Override // kotlin.collections.AbstractCollection, java.util.Collection
    public final /* bridge */ boolean contains(Object element) {
        if (element instanceof Float) {
            return contains(((Number) element).floatValue());
        }
        return false;
    }

    @Override // kotlin.collections.AbstractList, java.util.List
    public final /* bridge */ int indexOf(Object element) {
        if (element instanceof Float) {
            return indexOf(((Number) element).floatValue());
        }
        return -1;
    }

    @Override // kotlin.collections.AbstractList, java.util.List
    public final /* bridge */ int lastIndexOf(Object element) {
        if (element instanceof Float) {
            return lastIndexOf(((Number) element).floatValue());
        }
        return -1;
    }

    @Override // kotlin.collections.AbstractList, kotlin.collections.AbstractCollection
    public int getSize() {
        return this.$this_asList.length;
    }

    @Override // kotlin.collections.AbstractCollection, java.util.Collection
    public boolean isEmpty() {
        return this.$this_asList.length == 0;
    }

    public boolean contains(float element) {
        float[] $this$any$iv = this.$this_asList;
        for (float element$iv : $this$any$iv) {
            if (Float.floatToIntBits(element$iv) == Float.floatToIntBits(element)) {
                return true;
            }
        }
        return false;
    }

    @Override // kotlin.collections.AbstractList, java.util.List
    public Float get(int index) {
        return Float.valueOf(this.$this_asList[index]);
    }

    public int indexOf(float element) {
        float[] $this$indexOfFirst$iv = this.$this_asList;
        int length = $this$indexOfFirst$iv.length;
        for (int index$iv = 0; index$iv < length; index$iv++) {
            float it = $this$indexOfFirst$iv[index$iv];
            if (Float.floatToIntBits(it) == Float.floatToIntBits(element)) {
                return index$iv;
            }
        }
        return -1;
    }

    public int lastIndexOf(float element) {
        float[] $this$indexOfLast$iv = this.$this_asList;
        int length = $this$indexOfLast$iv.length - 1;
        if (length >= 0) {
            do {
                int index$iv = length;
                length--;
                float it = $this$indexOfLast$iv[index$iv];
                if (Float.floatToIntBits(it) == Float.floatToIntBits(element)) {
                    return index$iv;
                }
            } while (length >= 0);
            return -1;
        }
        return -1;
    }
}
