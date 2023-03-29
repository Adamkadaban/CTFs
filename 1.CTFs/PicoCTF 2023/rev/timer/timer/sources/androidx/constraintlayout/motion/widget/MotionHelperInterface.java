package androidx.constraintlayout.motion.widget;

import android.graphics.Canvas;
import android.view.View;
import androidx.constraintlayout.motion.widget.MotionLayout;
import java.util.HashMap;
/* loaded from: classes.dex */
public interface MotionHelperInterface extends Animatable, MotionLayout.TransitionListener {
    boolean isDecorator();

    boolean isUseOnHide();

    boolean isUsedOnShow();

    void onFinishedMotionScene(MotionLayout motionLayout);

    void onPostDraw(Canvas canvas);

    void onPreDraw(Canvas canvas);

    void onPreSetup(MotionLayout motionLayout, HashMap<View, MotionController> controllerMap);
}
