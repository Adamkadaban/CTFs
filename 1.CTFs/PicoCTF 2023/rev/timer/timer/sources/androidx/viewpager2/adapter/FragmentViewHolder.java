package androidx.viewpager2.adapter;

import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.core.view.ViewCompat;
import androidx.recyclerview.widget.RecyclerView;
/* loaded from: classes.dex */
public final class FragmentViewHolder extends RecyclerView.ViewHolder {
    private FragmentViewHolder(FrameLayout container) {
        super(container);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static FragmentViewHolder create(ViewGroup parent) {
        FrameLayout container = new FrameLayout(parent.getContext());
        container.setLayoutParams(new ViewGroup.LayoutParams(-1, -1));
        container.setId(ViewCompat.generateViewId());
        container.setSaveEnabled(false);
        return new FragmentViewHolder(container);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public FrameLayout getContainer() {
        return (FrameLayout) this.itemView;
    }
}
