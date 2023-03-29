package kotlin.collections;

import java.util.RandomAccess;
import kotlin.Metadata;
/* compiled from: _ArraysJvm.kt */
@Metadata(d1 = {"\u0000'\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\b*\u0001\u0000\b\n\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u00012\u00060\u0003j\u0002`\u0004J\u0011\u0010\t\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\u0002H\u0096\u0002J\u0016\u0010\f\u001a\u00020\u00022\u0006\u0010\r\u001a\u00020\u0006H\u0096\u0002¢\u0006\u0002\u0010\u000eJ\u0010\u0010\u000f\u001a\u00020\u00062\u0006\u0010\u000b\u001a\u00020\u0002H\u0016J\b\u0010\u0010\u001a\u00020\nH\u0016J\u0010\u0010\u0011\u001a\u00020\u00062\u0006\u0010\u000b\u001a\u00020\u0002H\u0016R\u0014\u0010\u0005\u001a\u00020\u00068VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0007\u0010\b¨\u0006\u0012"}, d2 = {"kotlin/collections/ArraysKt___ArraysJvmKt$asList$6", "Lkotlin/collections/AbstractList;", "", "Ljava/util/RandomAccess;", "Lkotlin/collections/RandomAccess;", "size", "", "getSize", "()I", "contains", "", "element", "get", "index", "(I)Ljava/lang/Double;", "indexOf", "isEmpty", "lastIndexOf", "kotlin-stdlib"}, k = 1, mv = {1, 6, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ArraysKt___ArraysJvmKt$asList$6 extends AbstractList<Double> implements RandomAccess {
    final /* synthetic */ double[] $this_asList;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ArraysKt___ArraysJvmKt$asList$6(double[] $receiver) {
        this.$this_asList = $receiver;
    }

    @Override // kotlin.collections.AbstractCollection, java.util.Collection
    public final /* bridge */ boolean contains(Object element) {
        if (element instanceof Double) {
            return contains(((Number) element).doubleValue());
        }
        return false;
    }

    @Override // kotlin.collections.AbstractList, java.util.List
    public final /* bridge */ int indexOf(Object element) {
        if (element instanceof Double) {
            return indexOf(((Number) element).doubleValue());
        }
        return -1;
    }

    @Override // kotlin.collections.AbstractList, java.util.List
    public final /* bridge */ int lastIndexOf(Object element) {
        if (element instanceof Double) {
            return lastIndexOf(((Number) element).doubleValue());
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

    public boolean contains(double element) {
        double[] $this$any$iv = this.$this_asList;
        for (double element$iv : $this$any$iv) {
            if (Double.doubleToLongBits(element$iv) == Double.doubleToLongBits(element)) {
                return true;
            }
        }
        return false;
    }

    @Override // kotlin.collections.AbstractList, java.util.List
    public Double get(int index) {
        return Double.valueOf(this.$this_asList[index]);
    }

    public int indexOf(double element) {
        double[] $this$indexOfFirst$iv = this.$this_asList;
        int length = $this$indexOfFirst$iv.length;
        for (int index$iv = 0; index$iv < length; index$iv++) {
            double it = $this$indexOfFirst$iv[index$iv];
            if (Double.doubleToLongBits(it) == Double.doubleToLongBits(element)) {
                return index$iv;
            }
        }
        return -1;
    }

    public int lastIndexOf(double element) {
        double[] $this$indexOfLast$iv = this.$this_asList;
        int length = $this$indexOfLast$iv.length - 1;
        if (length >= 0) {
            do {
                int index$iv = length;
                length--;
                double it = $this$indexOfLast$iv[index$iv];
                if (Double.doubleToLongBits(it) == Double.doubleToLongBits(element)) {
                    return index$iv;
                }
            } while (length >= 0);
            return -1;
        }
        return -1;
    }
}
