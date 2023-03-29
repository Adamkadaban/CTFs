package androidx.viewpager2.widget;

import android.view.View;
import android.view.ViewParent;
import androidx.core.util.Preconditions;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager2.widget.ViewPager2;
/* loaded from: classes.dex */
public final class MarginPageTransformer implements ViewPager2.PageTransformer {
    private final int mMarginPx;

    public MarginPageTransformer(int marginPx) {
        Preconditions.checkArgumentNonnegative(marginPx, "Margin must be non-negative");
        this.mMarginPx = marginPx;
    }

    @Override // androidx.viewpager2.widget.ViewPager2.PageTransformer
    public void transformPage(View page, float position) {
        ViewPager2 viewPager = requireViewPager(page);
        float offset = this.mMarginPx * position;
        if (viewPager.getOrientation() == 0) {
            page.setTranslationX(viewPager.isRtl() ? -offset : offset);
        } else {
            page.setTranslationY(offset);
        }
    }

    private ViewPager2 requireViewPager(View page) {
        ViewParent parent = page.getParent();
        ViewParent parentParent = parent.getParent();
        if ((parent instanceof RecyclerView) && (parentParent instanceof ViewPager2)) {
            return (ViewPager2) parentParent;
        }
        throw new IllegalStateException("Expected the page view to be managed by a ViewPager2 instance.");
    }
}
