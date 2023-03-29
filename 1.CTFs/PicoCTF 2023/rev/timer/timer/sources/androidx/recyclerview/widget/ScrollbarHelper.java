package androidx.recyclerview.widget;

import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class ScrollbarHelper {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static int computeScrollOffset(RecyclerView.State state, OrientationHelper orientation, View startChild, View endChild, RecyclerView.LayoutManager lm, boolean smoothScrollbarEnabled, boolean reverseLayout) {
        int itemsBefore;
        if (lm.getChildCount() == 0 || state.getItemCount() == 0 || startChild == null || endChild == null) {
            return 0;
        }
        int minPosition = Math.min(lm.getPosition(startChild), lm.getPosition(endChild));
        int maxPosition = Math.max(lm.getPosition(startChild), lm.getPosition(endChild));
        if (reverseLayout) {
            itemsBefore = Math.max(0, (state.getItemCount() - maxPosition) - 1);
        } else {
            itemsBefore = Math.max(0, minPosition);
        }
        if (!smoothScrollbarEnabled) {
            return itemsBefore;
        }
        int laidOutArea = Math.abs(orientation.getDecoratedEnd(endChild) - orientation.getDecoratedStart(startChild));
        int itemRange = Math.abs(lm.getPosition(startChild) - lm.getPosition(endChild)) + 1;
        float avgSizePerRow = laidOutArea / itemRange;
        return Math.round((itemsBefore * avgSizePerRow) + (orientation.getStartAfterPadding() - orientation.getDecoratedStart(startChild)));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int computeScrollExtent(RecyclerView.State state, OrientationHelper orientation, View startChild, View endChild, RecyclerView.LayoutManager lm, boolean smoothScrollbarEnabled) {
        if (lm.getChildCount() == 0 || state.getItemCount() == 0 || startChild == null || endChild == null) {
            return 0;
        }
        if (!smoothScrollbarEnabled) {
            return Math.abs(lm.getPosition(startChild) - lm.getPosition(endChild)) + 1;
        }
        int extend = orientation.getDecoratedEnd(endChild) - orientation.getDecoratedStart(startChild);
        return Math.min(orientation.getTotalSpace(), extend);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int computeScrollRange(RecyclerView.State state, OrientationHelper orientation, View startChild, View endChild, RecyclerView.LayoutManager lm, boolean smoothScrollbarEnabled) {
        if (lm.getChildCount() == 0 || state.getItemCount() == 0 || startChild == null || endChild == null) {
            return 0;
        }
        if (!smoothScrollbarEnabled) {
            return state.getItemCount();
        }
        int laidOutArea = orientation.getDecoratedEnd(endChild) - orientation.getDecoratedStart(startChild);
        int laidOutRange = Math.abs(lm.getPosition(startChild) - lm.getPosition(endChild)) + 1;
        return (int) ((laidOutArea / laidOutRange) * state.getItemCount());
    }

    private ScrollbarHelper() {
    }
}
