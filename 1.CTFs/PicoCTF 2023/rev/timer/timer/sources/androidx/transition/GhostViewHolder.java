package androidx.transition;

import android.os.Build;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.FrameLayout;
import java.util.ArrayList;
/* loaded from: classes.dex */
class GhostViewHolder extends FrameLayout {
    private boolean mAttached;
    private ViewGroup mParent;

    /* JADX INFO: Access modifiers changed from: package-private */
    public GhostViewHolder(ViewGroup parent) {
        super(parent.getContext());
        setClipChildren(false);
        this.mParent = parent;
        parent.setTag(R.id.ghost_view_holder, this);
        ViewGroupUtils.getOverlay(this.mParent).add(this);
        this.mAttached = true;
    }

    @Override // android.view.ViewGroup
    public void onViewAdded(View child) {
        if (!this.mAttached) {
            throw new IllegalStateException("This GhostViewHolder is detached!");
        }
        super.onViewAdded(child);
    }

    @Override // android.view.ViewGroup
    public void onViewRemoved(View child) {
        super.onViewRemoved(child);
        if ((getChildCount() == 1 && getChildAt(0) == child) || getChildCount() == 0) {
            this.mParent.setTag(R.id.ghost_view_holder, null);
            ViewGroupUtils.getOverlay(this.mParent).remove(this);
            this.mAttached = false;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static GhostViewHolder getHolder(ViewGroup parent) {
        return (GhostViewHolder) parent.getTag(R.id.ghost_view_holder);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void popToOverlayTop() {
        if (!this.mAttached) {
            throw new IllegalStateException("This GhostViewHolder is detached!");
        }
        ViewGroupUtils.getOverlay(this.mParent).remove(this);
        ViewGroupUtils.getOverlay(this.mParent).add(this);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void addGhostView(GhostViewPort ghostView) {
        ArrayList<View> viewParents = new ArrayList<>();
        getParents(ghostView.mView, viewParents);
        int index = getInsertIndex(viewParents);
        if (index < 0 || index >= getChildCount()) {
            addView(ghostView);
        } else {
            addView(ghostView, index);
        }
    }

    private int getInsertIndex(ArrayList<View> viewParents) {
        ArrayList<View> tempParents = new ArrayList<>();
        int low = 0;
        int high = getChildCount() - 1;
        while (low <= high) {
            int mid = (low + high) / 2;
            GhostViewPort midView = (GhostViewPort) getChildAt(mid);
            getParents(midView.mView, tempParents);
            if (isOnTop(viewParents, tempParents)) {
                low = mid + 1;
            } else {
                high = mid - 1;
            }
            tempParents.clear();
        }
        return low;
    }

    private static boolean isOnTop(ArrayList<View> viewParents, ArrayList<View> comparedWith) {
        if (viewParents.isEmpty() || comparedWith.isEmpty() || viewParents.get(0) != comparedWith.get(0)) {
            return true;
        }
        int depth = Math.min(viewParents.size(), comparedWith.size());
        for (int i = 1; i < depth; i++) {
            View viewParent = viewParents.get(i);
            View comparedWithParent = comparedWith.get(i);
            if (viewParent != comparedWithParent) {
                return isOnTop(viewParent, comparedWithParent);
            }
        }
        int i2 = comparedWith.size();
        return i2 == depth;
    }

    private static void getParents(View view, ArrayList<View> parents) {
        ViewParent parent = view.getParent();
        if (parent instanceof ViewGroup) {
            getParents((View) parent, parents);
        }
        parents.add(view);
    }

    private static boolean isOnTop(View view, View comparedWith) {
        ViewGroup parent = (ViewGroup) view.getParent();
        int childrenCount = parent.getChildCount();
        if (Build.VERSION.SDK_INT >= 21 && view.getZ() != comparedWith.getZ()) {
            return view.getZ() > comparedWith.getZ();
        }
        for (int i = 0; i < childrenCount; i++) {
            int childIndex = ViewGroupUtils.getChildDrawingOrder(parent, i);
            View child = parent.getChildAt(childIndex);
            if (child == view) {
                return false;
            }
            if (child == comparedWith) {
                return true;
            }
        }
        return true;
    }
}
