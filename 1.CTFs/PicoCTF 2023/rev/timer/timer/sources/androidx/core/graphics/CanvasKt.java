package androidx.core.graphics;

import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.RectF;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.InlineMarker;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: Canvas.kt */
@Metadata(d1 = {"\u0000>\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u000b\u001a1\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u00042\u0017\u0010\u0005\u001a\u0013\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00010\u0006¢\u0006\u0002\b\u0007H\u0086\bø\u0001\u0000\u001a1\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\b\u001a\u00020\t2\u0017\u0010\u0005\u001a\u0013\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00010\u0006¢\u0006\u0002\b\u0007H\u0086\bø\u0001\u0000\u001a1\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\b\u001a\u00020\n2\u0017\u0010\u0005\u001a\u0013\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00010\u0006¢\u0006\u0002\b\u0007H\u0086\bø\u0001\u0000\u001aI\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\f2\u0006\u0010\u000e\u001a\u00020\f2\u0006\u0010\u000f\u001a\u00020\f2\u0017\u0010\u0005\u001a\u0013\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00010\u0006¢\u0006\u0002\b\u0007H\u0086\bø\u0001\u0000\u001aI\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u000b\u001a\u00020\u00102\u0006\u0010\r\u001a\u00020\u00102\u0006\u0010\u000e\u001a\u00020\u00102\u0006\u0010\u000f\u001a\u00020\u00102\u0017\u0010\u0005\u001a\u0013\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00010\u0006¢\u0006\u0002\b\u0007H\u0086\bø\u0001\u0000\u001a3\u0010\u0011\u001a\u00020\u0001*\u00020\u00022\b\b\u0002\u0010\u0012\u001a\u00020\u00132\u0017\u0010\u0005\u001a\u0013\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00010\u0006¢\u0006\u0002\b\u0007H\u0086\bø\u0001\u0000\u001aG\u0010\u0014\u001a\u00020\u0001*\u00020\u00022\b\b\u0002\u0010\u0015\u001a\u00020\f2\b\b\u0002\u0010\u0016\u001a\u00020\f2\b\b\u0002\u0010\u0017\u001a\u00020\f2\u0017\u0010\u0005\u001a\u0013\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00010\u0006¢\u0006\u0002\b\u0007H\u0086\bø\u0001\u0000\u001a)\u0010\u0018\u001a\u00020\u0001*\u00020\u00022\u0017\u0010\u0005\u001a\u0013\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00010\u0006¢\u0006\u0002\b\u0007H\u0086\bø\u0001\u0000\u001aQ\u0010\u0019\u001a\u00020\u0001*\u00020\u00022\b\b\u0002\u0010\u001a\u001a\u00020\f2\b\b\u0002\u0010\u001b\u001a\u00020\f2\b\b\u0002\u0010\u0016\u001a\u00020\f2\b\b\u0002\u0010\u0017\u001a\u00020\f2\u0017\u0010\u0005\u001a\u0013\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00010\u0006¢\u0006\u0002\b\u0007H\u0086\bø\u0001\u0000\u001a=\u0010\u001c\u001a\u00020\u0001*\u00020\u00022\b\b\u0002\u0010\u001a\u001a\u00020\f2\b\b\u0002\u0010\u001b\u001a\u00020\f2\u0017\u0010\u0005\u001a\u0013\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00010\u0006¢\u0006\u0002\b\u0007H\u0086\bø\u0001\u0000\u001a=\u0010\u001d\u001a\u00020\u0001*\u00020\u00022\b\b\u0002\u0010\u001a\u001a\u00020\f2\b\b\u0002\u0010\u001b\u001a\u00020\f2\u0017\u0010\u0005\u001a\u0013\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00010\u0006¢\u0006\u0002\b\u0007H\u0086\bø\u0001\u0000\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u0006\u001e"}, d2 = {"withClip", "", "Landroid/graphics/Canvas;", "clipPath", "Landroid/graphics/Path;", "block", "Lkotlin/Function1;", "Lkotlin/ExtensionFunctionType;", "clipRect", "Landroid/graphics/Rect;", "Landroid/graphics/RectF;", "left", "", "top", "right", "bottom", "", "withMatrix", "matrix", "Landroid/graphics/Matrix;", "withRotation", "degrees", "pivotX", "pivotY", "withSave", "withScale", "x", "y", "withSkew", "withTranslation", "core-ktx_release"}, k = 2, mv = {1, 5, 1}, xi = 48)
/* loaded from: classes.dex */
public final class CanvasKt {
    public static final void withSave(Canvas $this$withSave, Function1<? super Canvas, Unit> block) {
        Intrinsics.checkNotNullParameter($this$withSave, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withSave.save();
        try {
            block.invoke($this$withSave);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withSave.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static /* synthetic */ void withTranslation$default(Canvas $this$withTranslation_u24default, float x, float y, Function1 block, int i, Object obj) {
        if ((i & 1) != 0) {
            x = 0.0f;
        }
        if ((i & 2) != 0) {
            y = 0.0f;
        }
        Intrinsics.checkNotNullParameter($this$withTranslation_u24default, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withTranslation_u24default.save();
        $this$withTranslation_u24default.translate(x, y);
        try {
            block.invoke($this$withTranslation_u24default);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withTranslation_u24default.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static final void withTranslation(Canvas $this$withTranslation, float x, float y, Function1<? super Canvas, Unit> block) {
        Intrinsics.checkNotNullParameter($this$withTranslation, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withTranslation.save();
        $this$withTranslation.translate(x, y);
        try {
            block.invoke($this$withTranslation);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withTranslation.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static /* synthetic */ void withRotation$default(Canvas $this$withRotation_u24default, float degrees, float pivotX, float pivotY, Function1 block, int i, Object obj) {
        if ((i & 1) != 0) {
            degrees = 0.0f;
        }
        if ((i & 2) != 0) {
            pivotX = 0.0f;
        }
        if ((i & 4) != 0) {
            pivotY = 0.0f;
        }
        Intrinsics.checkNotNullParameter($this$withRotation_u24default, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withRotation_u24default.save();
        $this$withRotation_u24default.rotate(degrees, pivotX, pivotY);
        try {
            block.invoke($this$withRotation_u24default);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withRotation_u24default.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static final void withRotation(Canvas $this$withRotation, float degrees, float pivotX, float pivotY, Function1<? super Canvas, Unit> block) {
        Intrinsics.checkNotNullParameter($this$withRotation, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withRotation.save();
        $this$withRotation.rotate(degrees, pivotX, pivotY);
        try {
            block.invoke($this$withRotation);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withRotation.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static /* synthetic */ void withScale$default(Canvas $this$withScale_u24default, float x, float y, float pivotX, float pivotY, Function1 block, int i, Object obj) {
        if ((i & 1) != 0) {
            x = 1.0f;
        }
        if ((i & 2) != 0) {
            y = 1.0f;
        }
        if ((i & 4) != 0) {
            pivotX = 0.0f;
        }
        if ((i & 8) != 0) {
            pivotY = 0.0f;
        }
        Intrinsics.checkNotNullParameter($this$withScale_u24default, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withScale_u24default.save();
        $this$withScale_u24default.scale(x, y, pivotX, pivotY);
        try {
            block.invoke($this$withScale_u24default);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withScale_u24default.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static final void withScale(Canvas $this$withScale, float x, float y, float pivotX, float pivotY, Function1<? super Canvas, Unit> block) {
        Intrinsics.checkNotNullParameter($this$withScale, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withScale.save();
        $this$withScale.scale(x, y, pivotX, pivotY);
        try {
            block.invoke($this$withScale);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withScale.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static /* synthetic */ void withSkew$default(Canvas $this$withSkew_u24default, float x, float y, Function1 block, int i, Object obj) {
        if ((i & 1) != 0) {
            x = 0.0f;
        }
        if ((i & 2) != 0) {
            y = 0.0f;
        }
        Intrinsics.checkNotNullParameter($this$withSkew_u24default, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withSkew_u24default.save();
        $this$withSkew_u24default.skew(x, y);
        try {
            block.invoke($this$withSkew_u24default);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withSkew_u24default.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static final void withSkew(Canvas $this$withSkew, float x, float y, Function1<? super Canvas, Unit> block) {
        Intrinsics.checkNotNullParameter($this$withSkew, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withSkew.save();
        $this$withSkew.skew(x, y);
        try {
            block.invoke($this$withSkew);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withSkew.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static /* synthetic */ void withMatrix$default(Canvas $this$withMatrix_u24default, Matrix matrix, Function1 block, int i, Object obj) {
        if ((i & 1) != 0) {
            matrix = new Matrix();
        }
        Intrinsics.checkNotNullParameter($this$withMatrix_u24default, "<this>");
        Intrinsics.checkNotNullParameter(matrix, "matrix");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withMatrix_u24default.save();
        $this$withMatrix_u24default.concat(matrix);
        try {
            block.invoke($this$withMatrix_u24default);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withMatrix_u24default.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static final void withMatrix(Canvas $this$withMatrix, Matrix matrix, Function1<? super Canvas, Unit> block) {
        Intrinsics.checkNotNullParameter($this$withMatrix, "<this>");
        Intrinsics.checkNotNullParameter(matrix, "matrix");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withMatrix.save();
        $this$withMatrix.concat(matrix);
        try {
            block.invoke($this$withMatrix);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withMatrix.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static final void withClip(Canvas $this$withClip, Rect clipRect, Function1<? super Canvas, Unit> block) {
        Intrinsics.checkNotNullParameter($this$withClip, "<this>");
        Intrinsics.checkNotNullParameter(clipRect, "clipRect");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withClip.save();
        $this$withClip.clipRect(clipRect);
        try {
            block.invoke($this$withClip);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withClip.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static final void withClip(Canvas $this$withClip, RectF clipRect, Function1<? super Canvas, Unit> block) {
        Intrinsics.checkNotNullParameter($this$withClip, "<this>");
        Intrinsics.checkNotNullParameter(clipRect, "clipRect");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withClip.save();
        $this$withClip.clipRect(clipRect);
        try {
            block.invoke($this$withClip);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withClip.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static final void withClip(Canvas $this$withClip, int left, int top, int right, int bottom, Function1<? super Canvas, Unit> block) {
        Intrinsics.checkNotNullParameter($this$withClip, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withClip.save();
        $this$withClip.clipRect(left, top, right, bottom);
        try {
            block.invoke($this$withClip);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withClip.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static final void withClip(Canvas $this$withClip, float left, float top, float right, float bottom, Function1<? super Canvas, Unit> block) {
        Intrinsics.checkNotNullParameter($this$withClip, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withClip.save();
        $this$withClip.clipRect(left, top, right, bottom);
        try {
            block.invoke($this$withClip);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withClip.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }

    public static final void withClip(Canvas $this$withClip, Path clipPath, Function1<? super Canvas, Unit> block) {
        Intrinsics.checkNotNullParameter($this$withClip, "<this>");
        Intrinsics.checkNotNullParameter(clipPath, "clipPath");
        Intrinsics.checkNotNullParameter(block, "block");
        int checkpoint = $this$withClip.save();
        $this$withClip.clipPath(clipPath);
        try {
            block.invoke($this$withClip);
        } finally {
            InlineMarker.finallyStart(1);
            $this$withClip.restoreToCount(checkpoint);
            InlineMarker.finallyEnd(1);
        }
    }
}
