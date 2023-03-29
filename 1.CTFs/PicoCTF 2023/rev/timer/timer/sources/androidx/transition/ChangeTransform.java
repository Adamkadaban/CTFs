package androidx.transition;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.PointF;
import android.os.Build;
import android.util.AttributeSet;
import android.util.Property;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.content.res.TypedArrayUtils;
import androidx.core.view.ViewCompat;
import org.xmlpull.v1.XmlPullParser;
/* loaded from: classes.dex */
public class ChangeTransform extends Transition {
    private static final String PROPNAME_INTERMEDIATE_MATRIX = "android:changeTransform:intermediateMatrix";
    private static final String PROPNAME_INTERMEDIATE_PARENT_MATRIX = "android:changeTransform:intermediateParentMatrix";
    private static final String PROPNAME_PARENT = "android:changeTransform:parent";
    private static final boolean SUPPORTS_VIEW_REMOVAL_SUPPRESSION;
    private boolean mReparent;
    private Matrix mTempMatrix;
    boolean mUseOverlay;
    private static final String PROPNAME_MATRIX = "android:changeTransform:matrix";
    private static final String PROPNAME_TRANSFORMS = "android:changeTransform:transforms";
    private static final String PROPNAME_PARENT_MATRIX = "android:changeTransform:parentMatrix";
    private static final String[] sTransitionProperties = {PROPNAME_MATRIX, PROPNAME_TRANSFORMS, PROPNAME_PARENT_MATRIX};
    private static final Property<PathAnimatorMatrix, float[]> NON_TRANSLATIONS_PROPERTY = new Property<PathAnimatorMatrix, float[]>(float[].class, "nonTranslations") { // from class: androidx.transition.ChangeTransform.1
        @Override // android.util.Property
        public float[] get(PathAnimatorMatrix object) {
            return null;
        }

        @Override // android.util.Property
        public void set(PathAnimatorMatrix object, float[] value) {
            object.setValues(value);
        }
    };
    private static final Property<PathAnimatorMatrix, PointF> TRANSLATIONS_PROPERTY = new Property<PathAnimatorMatrix, PointF>(PointF.class, "translations") { // from class: androidx.transition.ChangeTransform.2
        @Override // android.util.Property
        public PointF get(PathAnimatorMatrix object) {
            return null;
        }

        @Override // android.util.Property
        public void set(PathAnimatorMatrix object, PointF value) {
            object.setTranslation(value);
        }
    };

    static {
        SUPPORTS_VIEW_REMOVAL_SUPPRESSION = Build.VERSION.SDK_INT >= 21;
    }

    public ChangeTransform() {
        this.mUseOverlay = true;
        this.mReparent = true;
        this.mTempMatrix = new Matrix();
    }

    public ChangeTransform(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mUseOverlay = true;
        this.mReparent = true;
        this.mTempMatrix = new Matrix();
        TypedArray a = context.obtainStyledAttributes(attrs, Styleable.CHANGE_TRANSFORM);
        this.mUseOverlay = TypedArrayUtils.getNamedBoolean(a, (XmlPullParser) attrs, "reparentWithOverlay", 1, true);
        this.mReparent = TypedArrayUtils.getNamedBoolean(a, (XmlPullParser) attrs, "reparent", 0, true);
        a.recycle();
    }

    public boolean getReparentWithOverlay() {
        return this.mUseOverlay;
    }

    public void setReparentWithOverlay(boolean reparentWithOverlay) {
        this.mUseOverlay = reparentWithOverlay;
    }

    public boolean getReparent() {
        return this.mReparent;
    }

    public void setReparent(boolean reparent) {
        this.mReparent = reparent;
    }

    @Override // androidx.transition.Transition
    public String[] getTransitionProperties() {
        return sTransitionProperties;
    }

    private void captureValues(TransitionValues transitionValues) {
        Matrix matrix;
        View view = transitionValues.view;
        if (view.getVisibility() == 8) {
            return;
        }
        transitionValues.values.put(PROPNAME_PARENT, view.getParent());
        Transforms transforms = new Transforms(view);
        transitionValues.values.put(PROPNAME_TRANSFORMS, transforms);
        Matrix matrix2 = view.getMatrix();
        if (matrix2 == null || matrix2.isIdentity()) {
            matrix = null;
        } else {
            matrix = new Matrix(matrix2);
        }
        transitionValues.values.put(PROPNAME_MATRIX, matrix);
        if (this.mReparent) {
            Matrix parentMatrix = new Matrix();
            ViewGroup parent = (ViewGroup) view.getParent();
            ViewUtils.transformMatrixToGlobal(parent, parentMatrix);
            parentMatrix.preTranslate(-parent.getScrollX(), -parent.getScrollY());
            transitionValues.values.put(PROPNAME_PARENT_MATRIX, parentMatrix);
            transitionValues.values.put(PROPNAME_INTERMEDIATE_MATRIX, view.getTag(R.id.transition_transform));
            transitionValues.values.put(PROPNAME_INTERMEDIATE_PARENT_MATRIX, view.getTag(R.id.parent_matrix));
        }
    }

    @Override // androidx.transition.Transition
    public void captureStartValues(TransitionValues transitionValues) {
        captureValues(transitionValues);
        if (!SUPPORTS_VIEW_REMOVAL_SUPPRESSION) {
            ((ViewGroup) transitionValues.view.getParent()).startViewTransition(transitionValues.view);
        }
    }

    @Override // androidx.transition.Transition
    public void captureEndValues(TransitionValues transitionValues) {
        captureValues(transitionValues);
    }

    @Override // androidx.transition.Transition
    public Animator createAnimator(ViewGroup sceneRoot, TransitionValues startValues, TransitionValues endValues) {
        if (startValues != null && endValues != null && startValues.values.containsKey(PROPNAME_PARENT) && endValues.values.containsKey(PROPNAME_PARENT)) {
            ViewGroup startParent = (ViewGroup) startValues.values.get(PROPNAME_PARENT);
            ViewGroup endParent = (ViewGroup) endValues.values.get(PROPNAME_PARENT);
            boolean handleParentChange = this.mReparent && !parentsMatch(startParent, endParent);
            Matrix startMatrix = (Matrix) startValues.values.get(PROPNAME_INTERMEDIATE_MATRIX);
            if (startMatrix != null) {
                startValues.values.put(PROPNAME_MATRIX, startMatrix);
            }
            Matrix startParentMatrix = (Matrix) startValues.values.get(PROPNAME_INTERMEDIATE_PARENT_MATRIX);
            if (startParentMatrix != null) {
                startValues.values.put(PROPNAME_PARENT_MATRIX, startParentMatrix);
            }
            if (handleParentChange) {
                setMatricesForParent(startValues, endValues);
            }
            ObjectAnimator transformAnimator = createTransformAnimator(startValues, endValues, handleParentChange);
            if (handleParentChange && transformAnimator != null && this.mUseOverlay) {
                createGhostView(sceneRoot, startValues, endValues);
            } else if (!SUPPORTS_VIEW_REMOVAL_SUPPRESSION) {
                startParent.endViewTransition(startValues.view);
            }
            return transformAnimator;
        }
        return null;
    }

    private ObjectAnimator createTransformAnimator(TransitionValues startValues, TransitionValues endValues, final boolean handleParentChange) {
        Matrix startMatrix = (Matrix) startValues.values.get(PROPNAME_MATRIX);
        Matrix endMatrix = (Matrix) endValues.values.get(PROPNAME_MATRIX);
        if (startMatrix == null) {
            startMatrix = MatrixUtils.IDENTITY_MATRIX;
        }
        if (endMatrix == null) {
            endMatrix = MatrixUtils.IDENTITY_MATRIX;
        }
        if (startMatrix.equals(endMatrix)) {
            return null;
        }
        final Transforms transforms = (Transforms) endValues.values.get(PROPNAME_TRANSFORMS);
        final View view = endValues.view;
        setIdentityTransforms(view);
        float[] startMatrixValues = new float[9];
        startMatrix.getValues(startMatrixValues);
        float[] endMatrixValues = new float[9];
        endMatrix.getValues(endMatrixValues);
        final PathAnimatorMatrix pathAnimatorMatrix = new PathAnimatorMatrix(view, startMatrixValues);
        PropertyValuesHolder valuesProperty = PropertyValuesHolder.ofObject(NON_TRANSLATIONS_PROPERTY, new FloatArrayEvaluator(new float[9]), startMatrixValues, endMatrixValues);
        Path path = getPathMotion().getPath(startMatrixValues[2], startMatrixValues[5], endMatrixValues[2], endMatrixValues[5]);
        PropertyValuesHolder translationProperty = PropertyValuesHolderUtils.ofPointF(TRANSLATIONS_PROPERTY, path);
        ObjectAnimator animator = ObjectAnimator.ofPropertyValuesHolder(pathAnimatorMatrix, valuesProperty, translationProperty);
        final Matrix finalEndMatrix = endMatrix;
        AnimatorListenerAdapter listener = new AnimatorListenerAdapter() { // from class: androidx.transition.ChangeTransform.3
            private boolean mIsCanceled;
            private Matrix mTempMatrix = new Matrix();

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                this.mIsCanceled = true;
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (!this.mIsCanceled) {
                    if (handleParentChange && ChangeTransform.this.mUseOverlay) {
                        setCurrentMatrix(finalEndMatrix);
                    } else {
                        view.setTag(R.id.transition_transform, null);
                        view.setTag(R.id.parent_matrix, null);
                    }
                }
                ViewUtils.setAnimationMatrix(view, null);
                transforms.restore(view);
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorPauseListener
            public void onAnimationPause(Animator animation) {
                Matrix currentMatrix = pathAnimatorMatrix.getMatrix();
                setCurrentMatrix(currentMatrix);
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorPauseListener
            public void onAnimationResume(Animator animation) {
                ChangeTransform.setIdentityTransforms(view);
            }

            private void setCurrentMatrix(Matrix currentMatrix) {
                this.mTempMatrix.set(currentMatrix);
                view.setTag(R.id.transition_transform, this.mTempMatrix);
                transforms.restore(view);
            }
        };
        animator.addListener(listener);
        AnimatorUtils.addPauseListener(animator, listener);
        return animator;
    }

    private boolean parentsMatch(ViewGroup startParent, ViewGroup endParent) {
        if (!isValidTarget(startParent) || !isValidTarget(endParent)) {
            boolean parentsMatch = startParent == endParent;
            return parentsMatch;
        }
        TransitionValues endValues = getMatchedTransitionValues(startParent, true);
        if (endValues == null) {
            return false;
        }
        boolean parentsMatch2 = endParent == endValues.view;
        return parentsMatch2;
    }

    private void createGhostView(ViewGroup sceneRoot, TransitionValues startValues, TransitionValues endValues) {
        View view = endValues.view;
        Matrix endMatrix = (Matrix) endValues.values.get(PROPNAME_PARENT_MATRIX);
        Matrix localEndMatrix = new Matrix(endMatrix);
        ViewUtils.transformMatrixToLocal(sceneRoot, localEndMatrix);
        GhostView ghostView = GhostViewUtils.addGhost(view, sceneRoot, localEndMatrix);
        if (ghostView == null) {
            return;
        }
        ghostView.reserveEndViewTransition((ViewGroup) startValues.values.get(PROPNAME_PARENT), startValues.view);
        Transition outerTransition = this;
        while (outerTransition.mParent != null) {
            outerTransition = outerTransition.mParent;
        }
        GhostListener listener = new GhostListener(view, ghostView);
        outerTransition.addListener(listener);
        if (SUPPORTS_VIEW_REMOVAL_SUPPRESSION) {
            if (startValues.view != endValues.view) {
                ViewUtils.setTransitionAlpha(startValues.view, 0.0f);
            }
            ViewUtils.setTransitionAlpha(view, 1.0f);
        }
    }

    private void setMatricesForParent(TransitionValues startValues, TransitionValues endValues) {
        Matrix endParentMatrix = (Matrix) endValues.values.get(PROPNAME_PARENT_MATRIX);
        endValues.view.setTag(R.id.parent_matrix, endParentMatrix);
        Matrix toLocal = this.mTempMatrix;
        toLocal.reset();
        endParentMatrix.invert(toLocal);
        Matrix startLocal = (Matrix) startValues.values.get(PROPNAME_MATRIX);
        if (startLocal == null) {
            startLocal = new Matrix();
            startValues.values.put(PROPNAME_MATRIX, startLocal);
        }
        Matrix startParentMatrix = (Matrix) startValues.values.get(PROPNAME_PARENT_MATRIX);
        startLocal.postConcat(startParentMatrix);
        startLocal.postConcat(toLocal);
    }

    static void setIdentityTransforms(View view) {
        setTransforms(view, 0.0f, 0.0f, 0.0f, 1.0f, 1.0f, 0.0f, 0.0f, 0.0f);
    }

    static void setTransforms(View view, float translationX, float translationY, float translationZ, float scaleX, float scaleY, float rotationX, float rotationY, float rotationZ) {
        view.setTranslationX(translationX);
        view.setTranslationY(translationY);
        ViewCompat.setTranslationZ(view, translationZ);
        view.setScaleX(scaleX);
        view.setScaleY(scaleY);
        view.setRotationX(rotationX);
        view.setRotationY(rotationY);
        view.setRotation(rotationZ);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class Transforms {
        final float mRotationX;
        final float mRotationY;
        final float mRotationZ;
        final float mScaleX;
        final float mScaleY;
        final float mTranslationX;
        final float mTranslationY;
        final float mTranslationZ;

        Transforms(View view) {
            this.mTranslationX = view.getTranslationX();
            this.mTranslationY = view.getTranslationY();
            this.mTranslationZ = ViewCompat.getTranslationZ(view);
            this.mScaleX = view.getScaleX();
            this.mScaleY = view.getScaleY();
            this.mRotationX = view.getRotationX();
            this.mRotationY = view.getRotationY();
            this.mRotationZ = view.getRotation();
        }

        public void restore(View view) {
            ChangeTransform.setTransforms(view, this.mTranslationX, this.mTranslationY, this.mTranslationZ, this.mScaleX, this.mScaleY, this.mRotationX, this.mRotationY, this.mRotationZ);
        }

        public boolean equals(Object that) {
            if (that instanceof Transforms) {
                Transforms thatTransform = (Transforms) that;
                return thatTransform.mTranslationX == this.mTranslationX && thatTransform.mTranslationY == this.mTranslationY && thatTransform.mTranslationZ == this.mTranslationZ && thatTransform.mScaleX == this.mScaleX && thatTransform.mScaleY == this.mScaleY && thatTransform.mRotationX == this.mRotationX && thatTransform.mRotationY == this.mRotationY && thatTransform.mRotationZ == this.mRotationZ;
            }
            return false;
        }

        public int hashCode() {
            float f = this.mTranslationX;
            int code = f != 0.0f ? Float.floatToIntBits(f) : 0;
            int i = code * 31;
            float f2 = this.mTranslationY;
            int code2 = i + (f2 != 0.0f ? Float.floatToIntBits(f2) : 0);
            int code3 = code2 * 31;
            float f3 = this.mTranslationZ;
            int code4 = (code3 + (f3 != 0.0f ? Float.floatToIntBits(f3) : 0)) * 31;
            float f4 = this.mScaleX;
            int code5 = (code4 + (f4 != 0.0f ? Float.floatToIntBits(f4) : 0)) * 31;
            float f5 = this.mScaleY;
            int code6 = (code5 + (f5 != 0.0f ? Float.floatToIntBits(f5) : 0)) * 31;
            float f6 = this.mRotationX;
            int code7 = (code6 + (f6 != 0.0f ? Float.floatToIntBits(f6) : 0)) * 31;
            float f7 = this.mRotationY;
            int code8 = (code7 + (f7 != 0.0f ? Float.floatToIntBits(f7) : 0)) * 31;
            float f8 = this.mRotationZ;
            return code8 + (f8 != 0.0f ? Float.floatToIntBits(f8) : 0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class GhostListener extends TransitionListenerAdapter {
        private GhostView mGhostView;
        private View mView;

        GhostListener(View view, GhostView ghostView) {
            this.mView = view;
            this.mGhostView = ghostView;
        }

        @Override // androidx.transition.TransitionListenerAdapter, androidx.transition.Transition.TransitionListener
        public void onTransitionEnd(Transition transition) {
            transition.removeListener(this);
            GhostViewUtils.removeGhost(this.mView);
            this.mView.setTag(R.id.transition_transform, null);
            this.mView.setTag(R.id.parent_matrix, null);
        }

        @Override // androidx.transition.TransitionListenerAdapter, androidx.transition.Transition.TransitionListener
        public void onTransitionPause(Transition transition) {
            this.mGhostView.setVisibility(4);
        }

        @Override // androidx.transition.TransitionListenerAdapter, androidx.transition.Transition.TransitionListener
        public void onTransitionResume(Transition transition) {
            this.mGhostView.setVisibility(0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class PathAnimatorMatrix {
        private final Matrix mMatrix = new Matrix();
        private float mTranslationX;
        private float mTranslationY;
        private final float[] mValues;
        private final View mView;

        PathAnimatorMatrix(View view, float[] values) {
            this.mView = view;
            float[] fArr = (float[]) values.clone();
            this.mValues = fArr;
            this.mTranslationX = fArr[2];
            this.mTranslationY = fArr[5];
            setAnimationMatrix();
        }

        void setValues(float[] values) {
            System.arraycopy(values, 0, this.mValues, 0, values.length);
            setAnimationMatrix();
        }

        void setTranslation(PointF translation) {
            this.mTranslationX = translation.x;
            this.mTranslationY = translation.y;
            setAnimationMatrix();
        }

        private void setAnimationMatrix() {
            float[] fArr = this.mValues;
            fArr[2] = this.mTranslationX;
            fArr[5] = this.mTranslationY;
            this.mMatrix.setValues(fArr);
            ViewUtils.setAnimationMatrix(this.mView, this.mMatrix);
        }

        Matrix getMatrix() {
            return this.mMatrix;
        }
    }
}
