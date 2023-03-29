package com.google.android.material.transition.platform;

import android.app.Activity;
import android.app.SharedElementCallback;
import android.content.Context;
import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.os.Parcelable;
import android.transition.Transition;
import android.view.View;
import android.view.Window;
import androidx.constraintlayout.core.widgets.analyzer.BasicMeasure;
import androidx.core.graphics.BlendModeColorFilterCompat;
import androidx.core.graphics.BlendModeCompat;
import com.google.android.material.R;
import com.google.android.material.internal.ContextUtils;
import com.google.android.material.shape.ShapeAppearanceModel;
import com.google.android.material.shape.Shapeable;
import java.lang.ref.WeakReference;
import java.util.List;
import java.util.Map;
/* loaded from: classes.dex */
public class MaterialContainerTransformSharedElementCallback extends SharedElementCallback {
    private static WeakReference<View> capturedSharedElement;
    private Rect returnEndBounds;
    private boolean entering = true;
    private boolean transparentWindowBackgroundEnabled = true;
    private boolean sharedElementReenterTransitionEnabled = false;
    private ShapeProvider shapeProvider = new ShapeableViewShapeProvider();

    /* loaded from: classes.dex */
    public interface ShapeProvider {
        ShapeAppearanceModel provideShape(View view);
    }

    /* loaded from: classes.dex */
    public static class ShapeableViewShapeProvider implements ShapeProvider {
        @Override // com.google.android.material.transition.platform.MaterialContainerTransformSharedElementCallback.ShapeProvider
        public ShapeAppearanceModel provideShape(View sharedElement) {
            if (sharedElement instanceof Shapeable) {
                return ((Shapeable) sharedElement).getShapeAppearanceModel();
            }
            return null;
        }
    }

    @Override // android.app.SharedElementCallback
    public Parcelable onCaptureSharedElementSnapshot(View sharedElement, Matrix viewToGlobalMatrix, RectF screenBounds) {
        capturedSharedElement = new WeakReference<>(sharedElement);
        return super.onCaptureSharedElementSnapshot(sharedElement, viewToGlobalMatrix, screenBounds);
    }

    @Override // android.app.SharedElementCallback
    public View onCreateSnapshotView(Context context, Parcelable snapshot) {
        WeakReference<View> weakReference;
        View sharedElement;
        ShapeAppearanceModel shapeAppearanceModel;
        View snapshotView = super.onCreateSnapshotView(context, snapshot);
        if (snapshotView != null && (weakReference = capturedSharedElement) != null && this.shapeProvider != null && (sharedElement = weakReference.get()) != null && (shapeAppearanceModel = this.shapeProvider.provideShape(sharedElement)) != null) {
            snapshotView.setTag(R.id.mtrl_motion_snapshot_view, shapeAppearanceModel);
        }
        return snapshotView;
    }

    @Override // android.app.SharedElementCallback
    public void onMapSharedElements(List<String> names, Map<String, View> sharedElements) {
        View sharedElement;
        Activity activity;
        if (!names.isEmpty() && !sharedElements.isEmpty() && (sharedElement = sharedElements.get(names.get(0))) != null && (activity = ContextUtils.getActivity(sharedElement.getContext())) != null) {
            Window window = activity.getWindow();
            if (this.entering) {
                setUpEnterTransform(window);
            } else {
                setUpReturnTransform(activity, window);
            }
        }
    }

    @Override // android.app.SharedElementCallback
    public void onSharedElementStart(List<String> sharedElementNames, List<View> sharedElements, List<View> sharedElementSnapshots) {
        if (!sharedElements.isEmpty() && !sharedElementSnapshots.isEmpty()) {
            sharedElements.get(0).setTag(R.id.mtrl_motion_snapshot_view, sharedElementSnapshots.get(0));
        }
        if (!this.entering && !sharedElements.isEmpty() && this.returnEndBounds != null) {
            View sharedElement = sharedElements.get(0);
            int widthSpec = View.MeasureSpec.makeMeasureSpec(this.returnEndBounds.width(), BasicMeasure.EXACTLY);
            int heightSpec = View.MeasureSpec.makeMeasureSpec(this.returnEndBounds.height(), BasicMeasure.EXACTLY);
            sharedElement.measure(widthSpec, heightSpec);
            sharedElement.layout(this.returnEndBounds.left, this.returnEndBounds.top, this.returnEndBounds.right, this.returnEndBounds.bottom);
        }
    }

    @Override // android.app.SharedElementCallback
    public void onSharedElementEnd(List<String> sharedElementNames, List<View> sharedElements, List<View> sharedElementSnapshots) {
        if (!sharedElements.isEmpty() && (sharedElements.get(0).getTag(R.id.mtrl_motion_snapshot_view) instanceof View)) {
            sharedElements.get(0).setTag(R.id.mtrl_motion_snapshot_view, null);
        }
        if (!this.entering && !sharedElements.isEmpty()) {
            this.returnEndBounds = TransitionUtils.getRelativeBoundsRect(sharedElements.get(0));
        }
        this.entering = false;
    }

    public ShapeProvider getShapeProvider() {
        return this.shapeProvider;
    }

    public void setShapeProvider(ShapeProvider shapeProvider) {
        this.shapeProvider = shapeProvider;
    }

    public boolean isTransparentWindowBackgroundEnabled() {
        return this.transparentWindowBackgroundEnabled;
    }

    public void setTransparentWindowBackgroundEnabled(boolean transparentWindowBackgroundEnabled) {
        this.transparentWindowBackgroundEnabled = transparentWindowBackgroundEnabled;
    }

    public boolean isSharedElementReenterTransitionEnabled() {
        return this.sharedElementReenterTransitionEnabled;
    }

    public void setSharedElementReenterTransitionEnabled(boolean sharedElementReenterTransitionEnabled) {
        this.sharedElementReenterTransitionEnabled = sharedElementReenterTransitionEnabled;
    }

    private void setUpEnterTransform(final Window window) {
        Transition transition = window.getSharedElementEnterTransition();
        if (transition instanceof MaterialContainerTransform) {
            MaterialContainerTransform transform = (MaterialContainerTransform) transition;
            if (!this.sharedElementReenterTransitionEnabled) {
                window.setSharedElementReenterTransition(null);
            }
            if (this.transparentWindowBackgroundEnabled) {
                updateBackgroundFadeDuration(window, transform);
                transform.addListener(new TransitionListenerAdapter() { // from class: com.google.android.material.transition.platform.MaterialContainerTransformSharedElementCallback.1
                    @Override // com.google.android.material.transition.platform.TransitionListenerAdapter, android.transition.Transition.TransitionListener
                    public void onTransitionStart(Transition transition2) {
                        MaterialContainerTransformSharedElementCallback.removeWindowBackground(window);
                    }

                    @Override // com.google.android.material.transition.platform.TransitionListenerAdapter, android.transition.Transition.TransitionListener
                    public void onTransitionEnd(Transition transition2) {
                        MaterialContainerTransformSharedElementCallback.restoreWindowBackground(window);
                    }
                });
            }
        }
    }

    private void setUpReturnTransform(final Activity activity, final Window window) {
        Transition transition = window.getSharedElementReturnTransition();
        if (transition instanceof MaterialContainerTransform) {
            MaterialContainerTransform transform = (MaterialContainerTransform) transition;
            transform.setHoldAtEndEnabled(true);
            transform.addListener(new TransitionListenerAdapter() { // from class: com.google.android.material.transition.platform.MaterialContainerTransformSharedElementCallback.2
                @Override // com.google.android.material.transition.platform.TransitionListenerAdapter, android.transition.Transition.TransitionListener
                public void onTransitionEnd(Transition transition2) {
                    View sharedElement;
                    if (MaterialContainerTransformSharedElementCallback.capturedSharedElement != null && (sharedElement = (View) MaterialContainerTransformSharedElementCallback.capturedSharedElement.get()) != null) {
                        sharedElement.setAlpha(1.0f);
                        WeakReference unused = MaterialContainerTransformSharedElementCallback.capturedSharedElement = null;
                    }
                    activity.finish();
                    activity.overridePendingTransition(0, 0);
                }
            });
            if (this.transparentWindowBackgroundEnabled) {
                updateBackgroundFadeDuration(window, transform);
                transform.addListener(new TransitionListenerAdapter() { // from class: com.google.android.material.transition.platform.MaterialContainerTransformSharedElementCallback.3
                    @Override // com.google.android.material.transition.platform.TransitionListenerAdapter, android.transition.Transition.TransitionListener
                    public void onTransitionStart(Transition transition2) {
                        MaterialContainerTransformSharedElementCallback.removeWindowBackground(window);
                    }
                });
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void removeWindowBackground(Window window) {
        Drawable windowBackground = getWindowBackground(window);
        if (windowBackground == null) {
            return;
        }
        windowBackground.mutate().setColorFilter(BlendModeColorFilterCompat.createBlendModeColorFilterCompat(0, BlendModeCompat.CLEAR));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void restoreWindowBackground(Window window) {
        Drawable windowBackground = getWindowBackground(window);
        if (windowBackground == null) {
            return;
        }
        windowBackground.mutate().clearColorFilter();
    }

    private static Drawable getWindowBackground(Window window) {
        return window.getDecorView().getBackground();
    }

    private static void updateBackgroundFadeDuration(Window window, MaterialContainerTransform transform) {
        if (transform.getDuration() >= 0) {
            window.setTransitionBackgroundFadeDuration(transform.getDuration());
        }
    }
}
