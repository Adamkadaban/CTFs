package com.google.android.material.progressindicator;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import com.google.android.material.color.MaterialColors;
/* loaded from: classes.dex */
final class CircularDrawingDelegate extends DrawingDelegate<CircularProgressIndicatorSpec> {
    private float adjustedRadius;
    private int arcDirectionFactor;
    private float displayedCornerRadius;
    private float displayedTrackThickness;

    public CircularDrawingDelegate(CircularProgressIndicatorSpec spec) {
        super(spec);
        this.arcDirectionFactor = 1;
    }

    @Override // com.google.android.material.progressindicator.DrawingDelegate
    public int getPreferredWidth() {
        return getSize();
    }

    @Override // com.google.android.material.progressindicator.DrawingDelegate
    public int getPreferredHeight() {
        return getSize();
    }

    @Override // com.google.android.material.progressindicator.DrawingDelegate
    public void adjustCanvas(Canvas canvas, float trackThicknessFraction) {
        float outerRadiusWithInset = (((CircularProgressIndicatorSpec) this.spec).indicatorSize / 2.0f) + ((CircularProgressIndicatorSpec) this.spec).indicatorInset;
        canvas.translate(outerRadiusWithInset, outerRadiusWithInset);
        canvas.rotate(-90.0f);
        canvas.clipRect(-outerRadiusWithInset, -outerRadiusWithInset, outerRadiusWithInset, outerRadiusWithInset);
        this.arcDirectionFactor = ((CircularProgressIndicatorSpec) this.spec).indicatorDirection == 0 ? 1 : -1;
        this.displayedTrackThickness = ((CircularProgressIndicatorSpec) this.spec).trackThickness * trackThicknessFraction;
        this.displayedCornerRadius = ((CircularProgressIndicatorSpec) this.spec).trackCornerRadius * trackThicknessFraction;
        this.adjustedRadius = (((CircularProgressIndicatorSpec) this.spec).indicatorSize - ((CircularProgressIndicatorSpec) this.spec).trackThickness) / 2.0f;
        if ((this.drawable.isShowing() && ((CircularProgressIndicatorSpec) this.spec).showAnimationBehavior == 2) || (this.drawable.isHiding() && ((CircularProgressIndicatorSpec) this.spec).hideAnimationBehavior == 1)) {
            this.adjustedRadius += ((1.0f - trackThicknessFraction) * ((CircularProgressIndicatorSpec) this.spec).trackThickness) / 2.0f;
        } else if ((this.drawable.isShowing() && ((CircularProgressIndicatorSpec) this.spec).showAnimationBehavior == 1) || (this.drawable.isHiding() && ((CircularProgressIndicatorSpec) this.spec).hideAnimationBehavior == 2)) {
            this.adjustedRadius -= ((1.0f - trackThicknessFraction) * ((CircularProgressIndicatorSpec) this.spec).trackThickness) / 2.0f;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.progressindicator.DrawingDelegate
    public void fillIndicator(Canvas canvas, Paint paint, float startFraction, float endFraction, int color) {
        if (startFraction == endFraction) {
            return;
        }
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeCap(Paint.Cap.BUTT);
        paint.setAntiAlias(true);
        paint.setColor(color);
        paint.setStrokeWidth(this.displayedTrackThickness);
        int i = this.arcDirectionFactor;
        float startDegree = startFraction * 360.0f * i;
        float arcDegree = endFraction >= startFraction ? (endFraction - startFraction) * 360.0f * i : ((endFraction + 1.0f) - startFraction) * 360.0f * i;
        float f = this.adjustedRadius;
        RectF arcBound = new RectF(-f, -f, f, f);
        canvas.drawArc(arcBound, startDegree, arcDegree, false, paint);
        if (this.displayedCornerRadius > 0.0f && Math.abs(arcDegree) < 360.0f) {
            paint.setStyle(Paint.Style.FILL);
            drawRoundedEnd(canvas, paint, this.displayedTrackThickness, this.displayedCornerRadius, startDegree);
            drawRoundedEnd(canvas, paint, this.displayedTrackThickness, this.displayedCornerRadius, startDegree + arcDegree);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.progressindicator.DrawingDelegate
    public void fillTrack(Canvas canvas, Paint paint) {
        int trackColor = MaterialColors.compositeARGBWithAlpha(((CircularProgressIndicatorSpec) this.spec).trackColor, this.drawable.getAlpha());
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeCap(Paint.Cap.BUTT);
        paint.setAntiAlias(true);
        paint.setColor(trackColor);
        paint.setStrokeWidth(this.displayedTrackThickness);
        float f = this.adjustedRadius;
        RectF arcBound = new RectF(-f, -f, f, f);
        canvas.drawArc(arcBound, 0.0f, 360.0f, false, paint);
    }

    private int getSize() {
        return ((CircularProgressIndicatorSpec) this.spec).indicatorSize + (((CircularProgressIndicatorSpec) this.spec).indicatorInset * 2);
    }

    private void drawRoundedEnd(Canvas canvas, Paint paint, float trackSize, float cornerRadius, float positionInDeg) {
        canvas.save();
        canvas.rotate(positionInDeg);
        float f = this.adjustedRadius;
        RectF cornersBound = new RectF(f - (trackSize / 2.0f), cornerRadius, f + (trackSize / 2.0f), -cornerRadius);
        canvas.drawRoundRect(cornersBound, cornerRadius, cornerRadius, paint);
        canvas.restore();
    }
}
