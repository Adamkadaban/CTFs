package androidx.core.graphics;

import android.graphics.PointF;
import androidx.core.util.Preconditions;
/* loaded from: classes.dex */
public final class PathSegment {
    private final PointF mEnd;
    private final float mEndFraction;
    private final PointF mStart;
    private final float mStartFraction;

    public PathSegment(PointF start, float startFraction, PointF end, float endFraction) {
        this.mStart = (PointF) Preconditions.checkNotNull(start, "start == null");
        this.mStartFraction = startFraction;
        this.mEnd = (PointF) Preconditions.checkNotNull(end, "end == null");
        this.mEndFraction = endFraction;
    }

    public PointF getStart() {
        return this.mStart;
    }

    public float getStartFraction() {
        return this.mStartFraction;
    }

    public PointF getEnd() {
        return this.mEnd;
    }

    public float getEndFraction() {
        return this.mEndFraction;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof PathSegment) {
            PathSegment that = (PathSegment) o;
            return Float.compare(this.mStartFraction, that.mStartFraction) == 0 && Float.compare(this.mEndFraction, that.mEndFraction) == 0 && this.mStart.equals(that.mStart) && this.mEnd.equals(that.mEnd);
        }
        return false;
    }

    public int hashCode() {
        int result = this.mStart.hashCode();
        int i = result * 31;
        float f = this.mStartFraction;
        int result2 = i + (f != 0.0f ? Float.floatToIntBits(f) : 0);
        int result3 = ((result2 * 31) + this.mEnd.hashCode()) * 31;
        float f2 = this.mEndFraction;
        return result3 + (f2 != 0.0f ? Float.floatToIntBits(f2) : 0);
    }

    public String toString() {
        return "PathSegment{start=" + this.mStart + ", startFraction=" + this.mStartFraction + ", end=" + this.mEnd + ", endFraction=" + this.mEndFraction + '}';
    }
}
