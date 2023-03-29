package androidx.transition;

import android.graphics.Matrix;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.widget.ImageView;
import java.lang.reflect.Field;
/* loaded from: classes.dex */
class ImageViewUtils {
    private static Field sDrawMatrixField;
    private static boolean sDrawMatrixFieldFetched;
    private static boolean sTryHiddenAnimateTransform = true;

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void animateTransform(ImageView view, Matrix matrix) {
        if (Build.VERSION.SDK_INT >= 29) {
            view.animateTransform(matrix);
        } else if (matrix == null) {
            Drawable drawable = view.getDrawable();
            if (drawable != null) {
                int vwidth = (view.getWidth() - view.getPaddingLeft()) - view.getPaddingRight();
                int vheight = (view.getHeight() - view.getPaddingTop()) - view.getPaddingBottom();
                drawable.setBounds(0, 0, vwidth, vheight);
                view.invalidate();
            }
        } else if (Build.VERSION.SDK_INT >= 21) {
            hiddenAnimateTransform(view, matrix);
        } else {
            Drawable drawable2 = view.getDrawable();
            if (drawable2 != null) {
                drawable2.setBounds(0, 0, drawable2.getIntrinsicWidth(), drawable2.getIntrinsicHeight());
                Matrix drawMatrix = null;
                fetchDrawMatrixField();
                Field field = sDrawMatrixField;
                if (field != null) {
                    try {
                        drawMatrix = (Matrix) field.get(view);
                        if (drawMatrix == null) {
                            drawMatrix = new Matrix();
                            sDrawMatrixField.set(view, drawMatrix);
                        }
                    } catch (IllegalAccessException e) {
                    }
                }
                if (drawMatrix != null) {
                    drawMatrix.set(matrix);
                }
                view.invalidate();
            }
        }
    }

    private static void hiddenAnimateTransform(ImageView view, Matrix matrix) {
        if (sTryHiddenAnimateTransform) {
            try {
                view.animateTransform(matrix);
            } catch (NoSuchMethodError e) {
                sTryHiddenAnimateTransform = false;
            }
        }
    }

    private static void fetchDrawMatrixField() {
        if (!sDrawMatrixFieldFetched) {
            try {
                Field declaredField = ImageView.class.getDeclaredField("mDrawMatrix");
                sDrawMatrixField = declaredField;
                declaredField.setAccessible(true);
            } catch (NoSuchFieldException e) {
            }
            sDrawMatrixFieldFetched = true;
        }
    }

    private ImageViewUtils() {
    }
}
