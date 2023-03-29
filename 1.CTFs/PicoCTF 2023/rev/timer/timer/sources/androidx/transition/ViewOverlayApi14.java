package androidx.transition;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import androidx.core.view.ViewCompat;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class ViewOverlayApi14 implements ViewOverlayImpl {
    protected OverlayViewGroup mOverlayViewGroup;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ViewOverlayApi14(Context context, ViewGroup hostView, View requestingView) {
        this.mOverlayViewGroup = new OverlayViewGroup(context, hostView, requestingView, this);
    }

    static ViewGroup getContentView(View view) {
        View parent = view;
        while (parent != null) {
            if (parent.getId() == 16908290 && (parent instanceof ViewGroup)) {
                return (ViewGroup) parent;
            }
            if (parent.getParent() instanceof ViewGroup) {
                parent = (ViewGroup) parent.getParent();
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ViewOverlayApi14 createFrom(View view) {
        ViewGroup contentView = getContentView(view);
        if (contentView != null) {
            int numChildren = contentView.getChildCount();
            for (int i = 0; i < numChildren; i++) {
                View child = contentView.getChildAt(i);
                if (child instanceof OverlayViewGroup) {
                    return ((OverlayViewGroup) child).mViewOverlay;
                }
            }
            return new ViewGroupOverlayApi14(contentView.getContext(), contentView, view);
        }
        return null;
    }

    @Override // androidx.transition.ViewOverlayImpl
    public void add(Drawable drawable) {
        this.mOverlayViewGroup.add(drawable);
    }

    @Override // androidx.transition.ViewOverlayImpl
    public void remove(Drawable drawable) {
        this.mOverlayViewGroup.remove(drawable);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class OverlayViewGroup extends ViewGroup {
        static Method sInvalidateChildInParentFastMethod;
        private boolean mDisposed;
        ArrayList<Drawable> mDrawables;
        ViewGroup mHostView;
        View mRequestingView;
        ViewOverlayApi14 mViewOverlay;

        static {
            try {
                sInvalidateChildInParentFastMethod = ViewGroup.class.getDeclaredMethod("invalidateChildInParentFast", Integer.TYPE, Integer.TYPE, Rect.class);
            } catch (NoSuchMethodException e) {
            }
        }

        OverlayViewGroup(Context context, ViewGroup hostView, View requestingView, ViewOverlayApi14 viewOverlay) {
            super(context);
            this.mDrawables = null;
            this.mHostView = hostView;
            this.mRequestingView = requestingView;
            setRight(hostView.getWidth());
            setBottom(hostView.getHeight());
            hostView.addView(this);
            this.mViewOverlay = viewOverlay;
        }

        @Override // android.view.ViewGroup, android.view.View
        public boolean dispatchTouchEvent(MotionEvent ev) {
            return false;
        }

        public void add(Drawable drawable) {
            assertNotDisposed();
            if (this.mDrawables == null) {
                this.mDrawables = new ArrayList<>();
            }
            if (!this.mDrawables.contains(drawable)) {
                this.mDrawables.add(drawable);
                invalidate(drawable.getBounds());
                drawable.setCallback(this);
            }
        }

        public void remove(Drawable drawable) {
            ArrayList<Drawable> arrayList = this.mDrawables;
            if (arrayList != null) {
                arrayList.remove(drawable);
                invalidate(drawable.getBounds());
                drawable.setCallback(null);
                disposeIfEmpty();
            }
        }

        @Override // android.view.View
        protected boolean verifyDrawable(Drawable who) {
            ArrayList<Drawable> arrayList;
            return super.verifyDrawable(who) || ((arrayList = this.mDrawables) != null && arrayList.contains(who));
        }

        public void add(View child) {
            assertNotDisposed();
            if (child.getParent() instanceof ViewGroup) {
                ViewGroup parent = (ViewGroup) child.getParent();
                if (parent != this.mHostView && parent.getParent() != null && ViewCompat.isAttachedToWindow(parent)) {
                    int[] parentLocation = new int[2];
                    int[] hostViewLocation = new int[2];
                    parent.getLocationOnScreen(parentLocation);
                    this.mHostView.getLocationOnScreen(hostViewLocation);
                    ViewCompat.offsetLeftAndRight(child, parentLocation[0] - hostViewLocation[0]);
                    ViewCompat.offsetTopAndBottom(child, parentLocation[1] - hostViewLocation[1]);
                }
                parent.removeView(child);
                if (child.getParent() != null) {
                    parent.removeView(child);
                }
            }
            super.addView(child);
        }

        public void remove(View view) {
            super.removeView(view);
            disposeIfEmpty();
        }

        private void assertNotDisposed() {
            if (this.mDisposed) {
                throw new IllegalStateException("This overlay was disposed already. Please use a new one via ViewGroupUtils.getOverlay()");
            }
        }

        private void disposeIfEmpty() {
            if (getChildCount() == 0) {
                ArrayList<Drawable> arrayList = this.mDrawables;
                if (arrayList == null || arrayList.size() == 0) {
                    this.mDisposed = true;
                    this.mHostView.removeView(this);
                }
            }
        }

        @Override // android.view.View, android.graphics.drawable.Drawable.Callback
        public void invalidateDrawable(Drawable drawable) {
            invalidate(drawable.getBounds());
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void dispatchDraw(Canvas canvas) {
            int[] contentViewLocation = new int[2];
            int[] hostViewLocation = new int[2];
            this.mHostView.getLocationOnScreen(contentViewLocation);
            this.mRequestingView.getLocationOnScreen(hostViewLocation);
            canvas.translate(hostViewLocation[0] - contentViewLocation[0], hostViewLocation[1] - contentViewLocation[1]);
            canvas.clipRect(new Rect(0, 0, this.mRequestingView.getWidth(), this.mRequestingView.getHeight()));
            super.dispatchDraw(canvas);
            ArrayList<Drawable> arrayList = this.mDrawables;
            int numDrawables = arrayList != null ? arrayList.size() : 0;
            for (int i = 0; i < numDrawables; i++) {
                this.mDrawables.get(i).draw(canvas);
            }
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int l, int t, int r, int b) {
        }

        private void getOffset(int[] offset) {
            int[] contentViewLocation = new int[2];
            int[] hostViewLocation = new int[2];
            this.mHostView.getLocationOnScreen(contentViewLocation);
            this.mRequestingView.getLocationOnScreen(hostViewLocation);
            offset[0] = hostViewLocation[0] - contentViewLocation[0];
            offset[1] = hostViewLocation[1] - contentViewLocation[1];
        }

        protected ViewParent invalidateChildInParentFast(int left, int top, Rect dirty) {
            if ((this.mHostView instanceof ViewGroup) && sInvalidateChildInParentFastMethod != null) {
                try {
                    int[] offset = new int[2];
                    getOffset(offset);
                    sInvalidateChildInParentFastMethod.invoke(this.mHostView, Integer.valueOf(left), Integer.valueOf(top), dirty);
                    return null;
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                    return null;
                } catch (InvocationTargetException e2) {
                    e2.printStackTrace();
                    return null;
                }
            }
            return null;
        }

        @Override // android.view.ViewGroup, android.view.ViewParent
        public ViewParent invalidateChildInParent(int[] location, Rect dirty) {
            if (this.mHostView != null) {
                dirty.offset(location[0], location[1]);
                if (this.mHostView instanceof ViewGroup) {
                    location[0] = 0;
                    location[1] = 0;
                    int[] offset = new int[2];
                    getOffset(offset);
                    dirty.offset(offset[0], offset[1]);
                    return super.invalidateChildInParent(location, dirty);
                }
                invalidate(dirty);
                return null;
            }
            return null;
        }
    }
}
