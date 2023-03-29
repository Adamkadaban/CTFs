package androidx.constraintlayout.helper.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.util.Log;
import android.view.View;
import androidx.constraintlayout.motion.widget.Debug;
import androidx.constraintlayout.motion.widget.KeyAttributes;
import androidx.constraintlayout.motion.widget.KeyPosition;
import androidx.constraintlayout.motion.widget.MotionController;
import androidx.constraintlayout.motion.widget.MotionHelper;
import androidx.constraintlayout.motion.widget.MotionLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.R;
import java.util.HashMap;
/* loaded from: classes.dex */
public class MotionEffect extends MotionHelper {
    public static final int AUTO = -1;
    public static final int EAST = 2;
    public static final int NORTH = 0;
    public static final int SOUTH = 1;
    public static final String TAG = "FadeMove";
    private static final int UNSET = -1;
    public static final int WEST = 3;
    private int fadeMove;
    private float motionEffectAlpha;
    private int motionEffectEnd;
    private int motionEffectStart;
    private boolean motionEffectStrictMove;
    private int motionEffectTranslationX;
    private int motionEffectTranslationY;
    private int viewTransitionId;

    public MotionEffect(Context context) {
        super(context);
        this.motionEffectAlpha = 0.1f;
        this.motionEffectStart = 49;
        this.motionEffectEnd = 50;
        this.motionEffectTranslationX = 0;
        this.motionEffectTranslationY = 0;
        this.motionEffectStrictMove = true;
        this.viewTransitionId = -1;
        this.fadeMove = -1;
    }

    public MotionEffect(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.motionEffectAlpha = 0.1f;
        this.motionEffectStart = 49;
        this.motionEffectEnd = 50;
        this.motionEffectTranslationX = 0;
        this.motionEffectTranslationY = 0;
        this.motionEffectStrictMove = true;
        this.viewTransitionId = -1;
        this.fadeMove = -1;
        init(context, attrs);
    }

    public MotionEffect(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.motionEffectAlpha = 0.1f;
        this.motionEffectStart = 49;
        this.motionEffectEnd = 50;
        this.motionEffectTranslationX = 0;
        this.motionEffectTranslationY = 0;
        this.motionEffectStrictMove = true;
        this.viewTransitionId = -1;
        this.fadeMove = -1;
        init(context, attrs);
    }

    private void init(Context context, AttributeSet attrs) {
        if (attrs != null) {
            TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.MotionEffect);
            int N = a.getIndexCount();
            for (int i = 0; i < N; i++) {
                int attr = a.getIndex(i);
                if (attr == R.styleable.MotionEffect_motionEffect_start) {
                    int i2 = a.getInt(attr, this.motionEffectStart);
                    this.motionEffectStart = i2;
                    this.motionEffectStart = Math.max(Math.min(i2, 99), 0);
                } else if (attr == R.styleable.MotionEffect_motionEffect_end) {
                    int i3 = a.getInt(attr, this.motionEffectEnd);
                    this.motionEffectEnd = i3;
                    this.motionEffectEnd = Math.max(Math.min(i3, 99), 0);
                } else if (attr == R.styleable.MotionEffect_motionEffect_translationX) {
                    this.motionEffectTranslationX = a.getDimensionPixelOffset(attr, this.motionEffectTranslationX);
                } else if (attr == R.styleable.MotionEffect_motionEffect_translationY) {
                    this.motionEffectTranslationY = a.getDimensionPixelOffset(attr, this.motionEffectTranslationY);
                } else if (attr == R.styleable.MotionEffect_motionEffect_alpha) {
                    this.motionEffectAlpha = a.getFloat(attr, this.motionEffectAlpha);
                } else if (attr == R.styleable.MotionEffect_motionEffect_move) {
                    this.fadeMove = a.getInt(attr, this.fadeMove);
                } else if (attr == R.styleable.MotionEffect_motionEffect_strict) {
                    this.motionEffectStrictMove = a.getBoolean(attr, this.motionEffectStrictMove);
                } else if (attr == R.styleable.MotionEffect_motionEffect_viewTransition) {
                    this.viewTransitionId = a.getResourceId(attr, this.viewTransitionId);
                }
            }
            int i4 = this.motionEffectStart;
            int i5 = this.motionEffectEnd;
            if (i4 == i5) {
                if (i4 > 0) {
                    this.motionEffectStart = i4 - 1;
                } else {
                    this.motionEffectEnd = i5 + 1;
                }
            }
            a.recycle();
        }
    }

    @Override // androidx.constraintlayout.motion.widget.MotionHelper, androidx.constraintlayout.motion.widget.MotionHelperInterface
    public boolean isDecorator() {
        return true;
    }

    @Override // androidx.constraintlayout.motion.widget.MotionHelper, androidx.constraintlayout.motion.widget.MotionHelperInterface
    public void onPreSetup(MotionLayout motionLayout, HashMap<View, MotionController> controllerMap) {
        View[] views;
        HashMap<View, MotionController> hashMap = controllerMap;
        View[] views2 = getViews((ConstraintLayout) getParent());
        if (views2 == null) {
            Log.v(TAG, Debug.getLoc() + " views = null");
            return;
        }
        KeyAttributes alpha1 = new KeyAttributes();
        KeyAttributes alpha2 = new KeyAttributes();
        alpha1.setValue("alpha", Float.valueOf(this.motionEffectAlpha));
        alpha2.setValue("alpha", Float.valueOf(this.motionEffectAlpha));
        alpha1.setFramePosition(this.motionEffectStart);
        alpha2.setFramePosition(this.motionEffectEnd);
        KeyPosition stick1 = new KeyPosition();
        stick1.setFramePosition(this.motionEffectStart);
        stick1.setType(0);
        stick1.setValue("percentX", 0);
        stick1.setValue("percentY", 0);
        KeyPosition stick2 = new KeyPosition();
        stick2.setFramePosition(this.motionEffectEnd);
        stick2.setType(0);
        stick2.setValue("percentX", 1);
        stick2.setValue("percentY", 1);
        KeyAttributes translationX1 = null;
        KeyAttributes translationX2 = null;
        if (this.motionEffectTranslationX > 0) {
            translationX1 = new KeyAttributes();
            translationX2 = new KeyAttributes();
            translationX1.setValue("translationX", Integer.valueOf(this.motionEffectTranslationX));
            translationX1.setFramePosition(this.motionEffectEnd);
            translationX2.setValue("translationX", 0);
            translationX2.setFramePosition(this.motionEffectEnd - 1);
        }
        KeyAttributes translationY1 = null;
        KeyAttributes translationY2 = null;
        if (this.motionEffectTranslationY > 0) {
            translationY1 = new KeyAttributes();
            translationY2 = new KeyAttributes();
            translationY1.setValue("translationY", Integer.valueOf(this.motionEffectTranslationY));
            translationY1.setFramePosition(this.motionEffectEnd);
            translationY2.setValue("translationY", 0);
            translationY2.setFramePosition(this.motionEffectEnd - 1);
        }
        int moveDirection = this.fadeMove;
        if (this.fadeMove == -1) {
            int[] direction = new int[4];
            for (View view : views2) {
                MotionController mc = hashMap.get(view);
                if (mc != null) {
                    float x = mc.getFinalX() - mc.getStartX();
                    float y = mc.getFinalY() - mc.getStartY();
                    if (y < 0.0f) {
                        direction[1] = direction[1] + 1;
                    }
                    if (y > 0.0f) {
                        direction[0] = direction[0] + 1;
                    }
                    if (x > 0.0f) {
                        direction[3] = direction[3] + 1;
                    }
                    if (x < 0.0f) {
                        direction[2] = direction[2] + 1;
                    }
                }
            }
            int max = direction[0];
            moveDirection = 0;
            for (int i = 1; i < 4; i++) {
                if (max < direction[i]) {
                    max = direction[i];
                    moveDirection = i;
                }
            }
        }
        int i2 = 0;
        while (i2 < views2.length) {
            MotionController mc2 = hashMap.get(views2[i2]);
            if (mc2 == null) {
                views = views2;
            } else {
                float x2 = mc2.getFinalX() - mc2.getStartX();
                float y2 = mc2.getFinalY() - mc2.getStartY();
                boolean apply = true;
                if (moveDirection == 0) {
                    if (y2 > 0.0f && (!this.motionEffectStrictMove || x2 == 0.0f)) {
                        apply = false;
                    }
                } else if (moveDirection == 1) {
                    if (y2 < 0.0f && (!this.motionEffectStrictMove || x2 == 0.0f)) {
                        apply = false;
                    }
                } else if (moveDirection == 2) {
                    if (x2 < 0.0f && (!this.motionEffectStrictMove || y2 == 0.0f)) {
                        apply = false;
                    }
                } else if (moveDirection == 3 && x2 > 0.0f && (!this.motionEffectStrictMove || y2 == 0.0f)) {
                    apply = false;
                }
                if (!apply) {
                    views = views2;
                } else {
                    int i3 = this.viewTransitionId;
                    views = views2;
                    if (i3 == -1) {
                        mc2.addKey(alpha1);
                        mc2.addKey(alpha2);
                        mc2.addKey(stick1);
                        mc2.addKey(stick2);
                        if (this.motionEffectTranslationX > 0) {
                            mc2.addKey(translationX1);
                            mc2.addKey(translationX2);
                        }
                        if (this.motionEffectTranslationY > 0) {
                            mc2.addKey(translationY1);
                            mc2.addKey(translationY2);
                        }
                    } else {
                        motionLayout.applyViewTransition(i3, mc2);
                    }
                }
            }
            i2++;
            hashMap = controllerMap;
            views2 = views;
        }
    }
}
