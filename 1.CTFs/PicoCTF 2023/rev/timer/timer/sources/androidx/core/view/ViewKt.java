package androidx.core.view;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.Sequence;
import kotlin.sequences.SequencesKt;
/* compiled from: View.kt */
@Metadata(d1 = {"\u0000j\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\t\n\u0002\u0010\b\n\u0002\b\r\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\n\u001a5\u0010 \u001a\u00020!*\u00020\u00022#\b\u0004\u0010\"\u001a\u001d\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b$\u0012\b\b%\u0012\u0004\b\b(&\u0012\u0004\u0012\u00020!0#H\u0086\bø\u0001\u0000\u001a5\u0010'\u001a\u00020!*\u00020\u00022#\b\u0004\u0010\"\u001a\u001d\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b$\u0012\b\b%\u0012\u0004\b\b(&\u0012\u0004\u0012\u00020!0#H\u0086\bø\u0001\u0000\u001a5\u0010(\u001a\u00020!*\u00020\u00022#\b\u0004\u0010\"\u001a\u001d\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b$\u0012\b\b%\u0012\u0004\b\b(&\u0012\u0004\u0012\u00020!0#H\u0086\bø\u0001\u0000\u001a5\u0010)\u001a\u00020!*\u00020\u00022#\b\u0004\u0010\"\u001a\u001d\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b$\u0012\b\b%\u0012\u0004\b\b(&\u0012\u0004\u0012\u00020!0#H\u0086\bø\u0001\u0000\u001a5\u0010*\u001a\u00020+*\u00020\u00022#\b\u0004\u0010\"\u001a\u001d\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b$\u0012\b\b%\u0012\u0004\b\b(&\u0012\u0004\u0012\u00020!0#H\u0086\bø\u0001\u0000\u001a\u0014\u0010,\u001a\u00020-*\u00020\u00022\b\b\u0002\u0010.\u001a\u00020/\u001a(\u00100\u001a\u000201*\u00020\u00022\u0006\u00102\u001a\u0002032\u000e\b\u0004\u0010\"\u001a\b\u0012\u0004\u0012\u00020!04H\u0086\bø\u0001\u0000\u001a(\u00105\u001a\u000201*\u00020\u00022\u0006\u00102\u001a\u0002032\u000e\b\u0004\u0010\"\u001a\b\u0012\u0004\u0012\u00020!04H\u0087\bø\u0001\u0000\u001a\u0017\u00106\u001a\u00020!*\u00020\u00022\b\b\u0001\u00107\u001a\u00020\u0013H\u0086\b\u001a:\u00108\u001a\u00020!\"\n\b\u0000\u00109\u0018\u0001*\u00020:*\u00020\u00022\u0017\u0010;\u001a\u0013\u0012\u0004\u0012\u0002H9\u0012\u0004\u0012\u00020!0#¢\u0006\u0002\b<H\u0087\bø\u0001\u0000¢\u0006\u0002\b=\u001a)\u00108\u001a\u00020!*\u00020\u00022\u0017\u0010;\u001a\u0013\u0012\u0004\u0012\u00020:\u0012\u0004\u0012\u00020!0#¢\u0006\u0002\b<H\u0086\bø\u0001\u0000\u001a5\u0010>\u001a\u00020!*\u00020\u00022\b\b\u0003\u0010?\u001a\u00020\u00132\b\b\u0003\u0010@\u001a\u00020\u00132\b\b\u0003\u0010A\u001a\u00020\u00132\b\b\u0003\u0010B\u001a\u00020\u0013H\u0086\b\u001a5\u0010C\u001a\u00020!*\u00020\u00022\b\b\u0003\u0010D\u001a\u00020\u00132\b\b\u0003\u0010@\u001a\u00020\u00132\b\b\u0003\u0010E\u001a\u00020\u00132\b\b\u0003\u0010B\u001a\u00020\u0013H\u0087\b\"\u001b\u0010\u0000\u001a\b\u0012\u0004\u0012\u00020\u00020\u0001*\u00020\u00028F¢\u0006\u0006\u001a\u0004\b\u0003\u0010\u0004\"\u001b\u0010\u0005\u001a\b\u0012\u0004\u0012\u00020\u00060\u0001*\u00020\u00028F¢\u0006\u0006\u001a\u0004\b\u0007\u0010\u0004\"*\u0010\n\u001a\u00020\t*\u00020\u00022\u0006\u0010\b\u001a\u00020\t8Æ\u0002@Æ\u0002X\u0086\u000e¢\u0006\f\u001a\u0004\b\n\u0010\u000b\"\u0004\b\f\u0010\r\"*\u0010\u000e\u001a\u00020\t*\u00020\u00022\u0006\u0010\b\u001a\u00020\t8Æ\u0002@Æ\u0002X\u0086\u000e¢\u0006\f\u001a\u0004\b\u000e\u0010\u000b\"\u0004\b\u000f\u0010\r\"*\u0010\u0010\u001a\u00020\t*\u00020\u00022\u0006\u0010\b\u001a\u00020\t8Æ\u0002@Æ\u0002X\u0086\u000e¢\u0006\f\u001a\u0004\b\u0010\u0010\u000b\"\u0004\b\u0011\u0010\r\"\u0016\u0010\u0012\u001a\u00020\u0013*\u00020\u00028Æ\u0002¢\u0006\u0006\u001a\u0004\b\u0014\u0010\u0015\"\u0016\u0010\u0016\u001a\u00020\u0013*\u00020\u00028Æ\u0002¢\u0006\u0006\u001a\u0004\b\u0017\u0010\u0015\"\u0016\u0010\u0018\u001a\u00020\u0013*\u00020\u00028Æ\u0002¢\u0006\u0006\u001a\u0004\b\u0019\u0010\u0015\"\u0016\u0010\u001a\u001a\u00020\u0013*\u00020\u00028Æ\u0002¢\u0006\u0006\u001a\u0004\b\u001b\u0010\u0015\"\u0016\u0010\u001c\u001a\u00020\u0013*\u00020\u00028Æ\u0002¢\u0006\u0006\u001a\u0004\b\u001d\u0010\u0015\"\u0016\u0010\u001e\u001a\u00020\u0013*\u00020\u00028Æ\u0002¢\u0006\u0006\u001a\u0004\b\u001f\u0010\u0015\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u0006F"}, d2 = {"allViews", "Lkotlin/sequences/Sequence;", "Landroid/view/View;", "getAllViews", "(Landroid/view/View;)Lkotlin/sequences/Sequence;", "ancestors", "Landroid/view/ViewParent;", "getAncestors", "value", "", "isGone", "(Landroid/view/View;)Z", "setGone", "(Landroid/view/View;Z)V", "isInvisible", "setInvisible", "isVisible", "setVisible", "marginBottom", "", "getMarginBottom", "(Landroid/view/View;)I", "marginEnd", "getMarginEnd", "marginLeft", "getMarginLeft", "marginRight", "getMarginRight", "marginStart", "getMarginStart", "marginTop", "getMarginTop", "doOnAttach", "", "action", "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "view", "doOnDetach", "doOnLayout", "doOnNextLayout", "doOnPreDraw", "Landroidx/core/view/OneShotPreDrawListener;", "drawToBitmap", "Landroid/graphics/Bitmap;", "config", "Landroid/graphics/Bitmap$Config;", "postDelayed", "Ljava/lang/Runnable;", "delayInMillis", "", "Lkotlin/Function0;", "postOnAnimationDelayed", "setPadding", "size", "updateLayoutParams", "T", "Landroid/view/ViewGroup$LayoutParams;", "block", "Lkotlin/ExtensionFunctionType;", "updateLayoutParamsTyped", "updatePadding", "left", "top", "right", "bottom", "updatePaddingRelative", "start", "end", "core-ktx_release"}, k = 2, mv = {1, 5, 1}, xi = 48)
/* loaded from: classes.dex */
public final class ViewKt {
    public static final void doOnNextLayout(View $this$doOnNextLayout, final Function1<? super View, Unit> action) {
        Intrinsics.checkNotNullParameter($this$doOnNextLayout, "<this>");
        Intrinsics.checkNotNullParameter(action, "action");
        $this$doOnNextLayout.addOnLayoutChangeListener(new View.OnLayoutChangeListener() { // from class: androidx.core.view.ViewKt$doOnNextLayout$1
            @Override // android.view.View.OnLayoutChangeListener
            public void onLayoutChange(View view, int left, int top, int right, int bottom, int oldLeft, int oldTop, int oldRight, int oldBottom) {
                Intrinsics.checkNotNullParameter(view, "view");
                view.removeOnLayoutChangeListener(this);
                action.invoke(view);
            }
        });
    }

    public static final void doOnLayout(View $this$doOnLayout, final Function1<? super View, Unit> action) {
        Intrinsics.checkNotNullParameter($this$doOnLayout, "<this>");
        Intrinsics.checkNotNullParameter(action, "action");
        if (ViewCompat.isLaidOut($this$doOnLayout) && !$this$doOnLayout.isLayoutRequested()) {
            action.invoke($this$doOnLayout);
        } else {
            $this$doOnLayout.addOnLayoutChangeListener(new View.OnLayoutChangeListener() { // from class: androidx.core.view.ViewKt$doOnLayout$$inlined$doOnNextLayout$1
                @Override // android.view.View.OnLayoutChangeListener
                public void onLayoutChange(View view, int left, int top, int right, int bottom, int oldLeft, int oldTop, int oldRight, int oldBottom) {
                    Intrinsics.checkNotNullParameter(view, "view");
                    view.removeOnLayoutChangeListener(this);
                    Function1.this.invoke(view);
                }
            });
        }
    }

    public static final OneShotPreDrawListener doOnPreDraw(final View $this$doOnPreDraw, final Function1<? super View, Unit> action) {
        Intrinsics.checkNotNullParameter($this$doOnPreDraw, "<this>");
        Intrinsics.checkNotNullParameter(action, "action");
        OneShotPreDrawListener add = OneShotPreDrawListener.add($this$doOnPreDraw, new Runnable() { // from class: androidx.core.view.ViewKt$doOnPreDraw$1
            @Override // java.lang.Runnable
            public final void run() {
                action.invoke($this$doOnPreDraw);
            }
        });
        Intrinsics.checkNotNullExpressionValue(add, "View.doOnPreDraw(\n    cr…dd(this) { action(this) }");
        return add;
    }

    public static final void doOnAttach(final View $this$doOnAttach, final Function1<? super View, Unit> action) {
        Intrinsics.checkNotNullParameter($this$doOnAttach, "<this>");
        Intrinsics.checkNotNullParameter(action, "action");
        if (ViewCompat.isAttachedToWindow($this$doOnAttach)) {
            action.invoke($this$doOnAttach);
        } else {
            $this$doOnAttach.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() { // from class: androidx.core.view.ViewKt$doOnAttach$1
                @Override // android.view.View.OnAttachStateChangeListener
                public void onViewAttachedToWindow(View view) {
                    Intrinsics.checkNotNullParameter(view, "view");
                    $this$doOnAttach.removeOnAttachStateChangeListener(this);
                    action.invoke(view);
                }

                @Override // android.view.View.OnAttachStateChangeListener
                public void onViewDetachedFromWindow(View view) {
                    Intrinsics.checkNotNullParameter(view, "view");
                }
            });
        }
    }

    public static final void doOnDetach(final View $this$doOnDetach, final Function1<? super View, Unit> action) {
        Intrinsics.checkNotNullParameter($this$doOnDetach, "<this>");
        Intrinsics.checkNotNullParameter(action, "action");
        if (!ViewCompat.isAttachedToWindow($this$doOnDetach)) {
            action.invoke($this$doOnDetach);
        } else {
            $this$doOnDetach.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() { // from class: androidx.core.view.ViewKt$doOnDetach$1
                @Override // android.view.View.OnAttachStateChangeListener
                public void onViewAttachedToWindow(View view) {
                    Intrinsics.checkNotNullParameter(view, "view");
                }

                @Override // android.view.View.OnAttachStateChangeListener
                public void onViewDetachedFromWindow(View view) {
                    Intrinsics.checkNotNullParameter(view, "view");
                    $this$doOnDetach.removeOnAttachStateChangeListener(this);
                    action.invoke(view);
                }
            });
        }
    }

    public static /* synthetic */ void updatePaddingRelative$default(View $this$updatePaddingRelative_u24default, int start, int top, int end, int bottom, int i, Object obj) {
        if ((i & 1) != 0) {
            start = $this$updatePaddingRelative_u24default.getPaddingStart();
        }
        if ((i & 2) != 0) {
            top = $this$updatePaddingRelative_u24default.getPaddingTop();
        }
        if ((i & 4) != 0) {
            end = $this$updatePaddingRelative_u24default.getPaddingEnd();
        }
        if ((i & 8) != 0) {
            bottom = $this$updatePaddingRelative_u24default.getPaddingBottom();
        }
        Intrinsics.checkNotNullParameter($this$updatePaddingRelative_u24default, "<this>");
        $this$updatePaddingRelative_u24default.setPaddingRelative(start, top, end, bottom);
    }

    public static final void updatePaddingRelative(View $this$updatePaddingRelative, int start, int top, int end, int bottom) {
        Intrinsics.checkNotNullParameter($this$updatePaddingRelative, "<this>");
        $this$updatePaddingRelative.setPaddingRelative(start, top, end, bottom);
    }

    public static /* synthetic */ void updatePadding$default(View $this$updatePadding_u24default, int left, int top, int right, int bottom, int i, Object obj) {
        if ((i & 1) != 0) {
            left = $this$updatePadding_u24default.getPaddingLeft();
        }
        if ((i & 2) != 0) {
            top = $this$updatePadding_u24default.getPaddingTop();
        }
        if ((i & 4) != 0) {
            right = $this$updatePadding_u24default.getPaddingRight();
        }
        if ((i & 8) != 0) {
            bottom = $this$updatePadding_u24default.getPaddingBottom();
        }
        Intrinsics.checkNotNullParameter($this$updatePadding_u24default, "<this>");
        $this$updatePadding_u24default.setPadding(left, top, right, bottom);
    }

    public static final void updatePadding(View $this$updatePadding, int left, int top, int right, int bottom) {
        Intrinsics.checkNotNullParameter($this$updatePadding, "<this>");
        $this$updatePadding.setPadding(left, top, right, bottom);
    }

    public static final void setPadding(View $this$setPadding, int size) {
        Intrinsics.checkNotNullParameter($this$setPadding, "<this>");
        $this$setPadding.setPadding(size, size, size, size);
    }

    public static final Runnable postDelayed(View $this$postDelayed, long delayInMillis, final Function0<Unit> action) {
        Intrinsics.checkNotNullParameter($this$postDelayed, "<this>");
        Intrinsics.checkNotNullParameter(action, "action");
        Runnable runnable = new Runnable() { // from class: androidx.core.view.ViewKt$postDelayed$runnable$1
            @Override // java.lang.Runnable
            public final void run() {
                action.invoke();
            }
        };
        $this$postDelayed.postDelayed(runnable, delayInMillis);
        return runnable;
    }

    public static final Runnable postOnAnimationDelayed(View $this$postOnAnimationDelayed, long delayInMillis, final Function0<Unit> action) {
        Intrinsics.checkNotNullParameter($this$postOnAnimationDelayed, "<this>");
        Intrinsics.checkNotNullParameter(action, "action");
        Runnable runnable = new Runnable() { // from class: androidx.core.view.ViewKt$postOnAnimationDelayed$runnable$1
            @Override // java.lang.Runnable
            public final void run() {
                action.invoke();
            }
        };
        $this$postOnAnimationDelayed.postOnAnimationDelayed(runnable, delayInMillis);
        return runnable;
    }

    public static /* synthetic */ Bitmap drawToBitmap$default(View view, Bitmap.Config config, int i, Object obj) {
        if ((i & 1) != 0) {
            config = Bitmap.Config.ARGB_8888;
        }
        return drawToBitmap(view, config);
    }

    public static final Bitmap drawToBitmap(View $this$drawToBitmap, Bitmap.Config config) {
        Intrinsics.checkNotNullParameter($this$drawToBitmap, "<this>");
        Intrinsics.checkNotNullParameter(config, "config");
        if (!ViewCompat.isLaidOut($this$drawToBitmap)) {
            throw new IllegalStateException("View needs to be laid out before calling drawToBitmap()");
        }
        Bitmap $this$applyCanvas$iv = Bitmap.createBitmap($this$drawToBitmap.getWidth(), $this$drawToBitmap.getHeight(), config);
        Intrinsics.checkNotNullExpressionValue($this$applyCanvas$iv, "createBitmap(width, height, config)");
        Canvas c$iv = new Canvas($this$applyCanvas$iv);
        c$iv.translate(-$this$drawToBitmap.getScrollX(), -$this$drawToBitmap.getScrollY());
        $this$drawToBitmap.draw(c$iv);
        return $this$applyCanvas$iv;
    }

    public static final boolean isVisible(View $this$isVisible) {
        Intrinsics.checkNotNullParameter($this$isVisible, "<this>");
        return $this$isVisible.getVisibility() == 0;
    }

    public static final void setVisible(View $this$isVisible, boolean value) {
        Intrinsics.checkNotNullParameter($this$isVisible, "<this>");
        $this$isVisible.setVisibility(value ? 0 : 8);
    }

    public static final boolean isInvisible(View $this$isInvisible) {
        Intrinsics.checkNotNullParameter($this$isInvisible, "<this>");
        return $this$isInvisible.getVisibility() == 4;
    }

    public static final void setInvisible(View $this$isInvisible, boolean value) {
        Intrinsics.checkNotNullParameter($this$isInvisible, "<this>");
        $this$isInvisible.setVisibility(value ? 4 : 0);
    }

    public static final boolean isGone(View $this$isGone) {
        Intrinsics.checkNotNullParameter($this$isGone, "<this>");
        return $this$isGone.getVisibility() == 8;
    }

    public static final void setGone(View $this$isGone, boolean value) {
        Intrinsics.checkNotNullParameter($this$isGone, "<this>");
        $this$isGone.setVisibility(value ? 8 : 0);
    }

    public static final void updateLayoutParams(View $this$updateLayoutParams, Function1<? super ViewGroup.LayoutParams, Unit> block) {
        Intrinsics.checkNotNullParameter($this$updateLayoutParams, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        ViewGroup.LayoutParams params$iv = $this$updateLayoutParams.getLayoutParams();
        if (params$iv == null) {
            throw new NullPointerException("null cannot be cast to non-null type android.view.ViewGroup.LayoutParams");
        }
        block.invoke(params$iv);
        $this$updateLayoutParams.setLayoutParams(params$iv);
    }

    public static final /* synthetic */ <T extends ViewGroup.LayoutParams> void updateLayoutParamsTyped(View $this$updateLayoutParams, Function1<? super T, Unit> block) {
        Intrinsics.checkNotNullParameter($this$updateLayoutParams, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        ViewGroup.LayoutParams layoutParams = $this$updateLayoutParams.getLayoutParams();
        Intrinsics.reifiedOperationMarker(1, "T");
        ViewGroup.LayoutParams params = layoutParams;
        block.invoke(params);
        $this$updateLayoutParams.setLayoutParams(params);
    }

    public static final int getMarginLeft(View $this$marginLeft) {
        Intrinsics.checkNotNullParameter($this$marginLeft, "<this>");
        ViewGroup.LayoutParams layoutParams = $this$marginLeft.getLayoutParams();
        ViewGroup.MarginLayoutParams marginLayoutParams = layoutParams instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) layoutParams : null;
        if (marginLayoutParams == null) {
            return 0;
        }
        return marginLayoutParams.leftMargin;
    }

    public static final int getMarginTop(View $this$marginTop) {
        Intrinsics.checkNotNullParameter($this$marginTop, "<this>");
        ViewGroup.LayoutParams layoutParams = $this$marginTop.getLayoutParams();
        ViewGroup.MarginLayoutParams marginLayoutParams = layoutParams instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) layoutParams : null;
        if (marginLayoutParams == null) {
            return 0;
        }
        return marginLayoutParams.topMargin;
    }

    public static final int getMarginRight(View $this$marginRight) {
        Intrinsics.checkNotNullParameter($this$marginRight, "<this>");
        ViewGroup.LayoutParams layoutParams = $this$marginRight.getLayoutParams();
        ViewGroup.MarginLayoutParams marginLayoutParams = layoutParams instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) layoutParams : null;
        if (marginLayoutParams == null) {
            return 0;
        }
        return marginLayoutParams.rightMargin;
    }

    public static final int getMarginBottom(View $this$marginBottom) {
        Intrinsics.checkNotNullParameter($this$marginBottom, "<this>");
        ViewGroup.LayoutParams layoutParams = $this$marginBottom.getLayoutParams();
        ViewGroup.MarginLayoutParams marginLayoutParams = layoutParams instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) layoutParams : null;
        if (marginLayoutParams == null) {
            return 0;
        }
        return marginLayoutParams.bottomMargin;
    }

    public static final int getMarginStart(View $this$marginStart) {
        Intrinsics.checkNotNullParameter($this$marginStart, "<this>");
        ViewGroup.LayoutParams lp = $this$marginStart.getLayoutParams();
        if (lp instanceof ViewGroup.MarginLayoutParams) {
            return MarginLayoutParamsCompat.getMarginStart((ViewGroup.MarginLayoutParams) lp);
        }
        return 0;
    }

    public static final int getMarginEnd(View $this$marginEnd) {
        Intrinsics.checkNotNullParameter($this$marginEnd, "<this>");
        ViewGroup.LayoutParams lp = $this$marginEnd.getLayoutParams();
        if (lp instanceof ViewGroup.MarginLayoutParams) {
            return MarginLayoutParamsCompat.getMarginEnd((ViewGroup.MarginLayoutParams) lp);
        }
        return 0;
    }

    public static final Sequence<ViewParent> getAncestors(View $this$ancestors) {
        Intrinsics.checkNotNullParameter($this$ancestors, "<this>");
        return SequencesKt.generateSequence($this$ancestors.getParent(), ViewKt$ancestors$1.INSTANCE);
    }

    public static final Sequence<View> getAllViews(View $this$allViews) {
        Intrinsics.checkNotNullParameter($this$allViews, "<this>");
        return SequencesKt.sequence(new ViewKt$allViews$1($this$allViews, null));
    }
}
