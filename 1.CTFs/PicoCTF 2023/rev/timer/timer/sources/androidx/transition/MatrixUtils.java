package androidx.transition;

import android.graphics.Matrix;
import android.graphics.RectF;
/* loaded from: classes.dex */
class MatrixUtils {
    static final Matrix IDENTITY_MATRIX = new Matrix() { // from class: androidx.transition.MatrixUtils.1
        void oops() {
            throw new IllegalStateException("Matrix can not be modified");
        }

        @Override // android.graphics.Matrix
        public void set(Matrix src) {
            oops();
        }

        @Override // android.graphics.Matrix
        public void reset() {
            oops();
        }

        @Override // android.graphics.Matrix
        public void setTranslate(float dx, float dy) {
            oops();
        }

        @Override // android.graphics.Matrix
        public void setScale(float sx, float sy, float px, float py) {
            oops();
        }

        @Override // android.graphics.Matrix
        public void setScale(float sx, float sy) {
            oops();
        }

        @Override // android.graphics.Matrix
        public void setRotate(float degrees, float px, float py) {
            oops();
        }

        @Override // android.graphics.Matrix
        public void setRotate(float degrees) {
            oops();
        }

        @Override // android.graphics.Matrix
        public void setSinCos(float sinValue, float cosValue, float px, float py) {
            oops();
        }

        @Override // android.graphics.Matrix
        public void setSinCos(float sinValue, float cosValue) {
            oops();
        }

        @Override // android.graphics.Matrix
        public void setSkew(float kx, float ky, float px, float py) {
            oops();
        }

        @Override // android.graphics.Matrix
        public void setSkew(float kx, float ky) {
            oops();
        }

        @Override // android.graphics.Matrix
        public boolean setConcat(Matrix a, Matrix b) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean preTranslate(float dx, float dy) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean preScale(float sx, float sy, float px, float py) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean preScale(float sx, float sy) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean preRotate(float degrees, float px, float py) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean preRotate(float degrees) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean preSkew(float kx, float ky, float px, float py) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean preSkew(float kx, float ky) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean preConcat(Matrix other) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean postTranslate(float dx, float dy) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean postScale(float sx, float sy, float px, float py) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean postScale(float sx, float sy) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean postRotate(float degrees, float px, float py) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean postRotate(float degrees) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean postSkew(float kx, float ky, float px, float py) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean postSkew(float kx, float ky) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean postConcat(Matrix other) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean setRectToRect(RectF src, RectF dst, Matrix.ScaleToFit stf) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public boolean setPolyToPoly(float[] src, int srcIndex, float[] dst, int dstIndex, int pointCount) {
            oops();
            return false;
        }

        @Override // android.graphics.Matrix
        public void setValues(float[] values) {
            oops();
        }
    };

    private MatrixUtils() {
    }
}
