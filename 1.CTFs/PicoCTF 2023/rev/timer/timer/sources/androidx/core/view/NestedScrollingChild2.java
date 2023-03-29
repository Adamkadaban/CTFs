package androidx.core.view;
/* loaded from: classes.dex */
public interface NestedScrollingChild2 extends NestedScrollingChild {
    boolean dispatchNestedPreScroll(int i, int i2, int[] iArr, int[] iArr2, int i3);

    boolean dispatchNestedScroll(int i, int i2, int i3, int i4, int[] iArr, int i5);

    boolean hasNestedScrollingParent(int i);

    boolean startNestedScroll(int i, int i2);

    void stopNestedScroll(int i);
}
