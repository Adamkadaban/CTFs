package androidx.constraintlayout.core.state;

import androidx.constraintlayout.core.motion.Motion;
import androidx.constraintlayout.core.motion.MotionWidget;
import androidx.constraintlayout.core.motion.key.MotionKeyAttributes;
import androidx.constraintlayout.core.motion.key.MotionKeyCycle;
import androidx.constraintlayout.core.motion.key.MotionKeyPosition;
import androidx.constraintlayout.core.motion.utils.Easing;
import androidx.constraintlayout.core.motion.utils.KeyCache;
import androidx.constraintlayout.core.motion.utils.TypedBundle;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import androidx.constraintlayout.core.widgets.ConstraintWidgetContainer;
import java.util.ArrayList;
import java.util.HashMap;
/* loaded from: classes.dex */
public class Transition implements TypedValues {
    static final int ANTICIPATE = 6;
    static final int BOUNCE = 4;
    static final int EASE_IN = 1;
    static final int EASE_IN_OUT = 0;
    static final int EASE_OUT = 2;
    public static final int END = 1;
    public static final int INTERPOLATED = 2;
    private static final int INTERPOLATOR_REFERENCE_ID = -2;
    static final int LINEAR = 3;
    static final int OVERSHOOT = 5;
    private static final int SPLINE_STRING = -1;
    public static final int START = 0;
    HashMap<Integer, HashMap<String, KeyPosition>> keyPositions = new HashMap<>();
    private HashMap<String, WidgetState> state = new HashMap<>();
    TypedBundle mBundle = new TypedBundle();
    private int mDefaultInterpolator = 0;
    private String mDefaultInterpolatorString = null;
    private Easing mEasing = null;
    private int mAutoTransition = 0;
    private int mDuration = 400;
    private float mStagger = 0.0f;

    public static Interpolator getInterpolator(int interpolator, final String interpolatorString) {
        switch (interpolator) {
            case -1:
                return new Interpolator() { // from class: androidx.constraintlayout.core.state.Transition$$ExternalSyntheticLambda0
                    @Override // androidx.constraintlayout.core.state.Interpolator
                    public final float getInterpolation(float f) {
                        return Transition.lambda$getInterpolator$0(interpolatorString, f);
                    }
                };
            case 0:
                return Transition$$ExternalSyntheticLambda1.INSTANCE;
            case 1:
                return Transition$$ExternalSyntheticLambda2.INSTANCE;
            case 2:
                return Transition$$ExternalSyntheticLambda3.INSTANCE;
            case 3:
                return Transition$$ExternalSyntheticLambda4.INSTANCE;
            case 4:
                return Transition$$ExternalSyntheticLambda7.INSTANCE;
            case 5:
                return Transition$$ExternalSyntheticLambda6.INSTANCE;
            case 6:
                return Transition$$ExternalSyntheticLambda5.INSTANCE;
            default:
                return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static /* synthetic */ float lambda$getInterpolator$0(String interpolatorString, float v) {
        return (float) Easing.getInterpolator(interpolatorString).get(v);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static /* synthetic */ float lambda$getInterpolator$1(float v) {
        return (float) Easing.getInterpolator("standard").get(v);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static /* synthetic */ float lambda$getInterpolator$2(float v) {
        return (float) Easing.getInterpolator("accelerate").get(v);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static /* synthetic */ float lambda$getInterpolator$3(float v) {
        return (float) Easing.getInterpolator("decelerate").get(v);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static /* synthetic */ float lambda$getInterpolator$4(float v) {
        return (float) Easing.getInterpolator("linear").get(v);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static /* synthetic */ float lambda$getInterpolator$5(float v) {
        return (float) Easing.getInterpolator("anticipate").get(v);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static /* synthetic */ float lambda$getInterpolator$6(float v) {
        return (float) Easing.getInterpolator("overshoot").get(v);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static /* synthetic */ float lambda$getInterpolator$7(float v) {
        return (float) Easing.getInterpolator("spline(0.0, 0.2, 0.4, 0.6, 0.8 ,1.0, 0.8, 1.0, 0.9, 1.0)").get(v);
    }

    public KeyPosition findPreviousPosition(String target, int frameNumber) {
        KeyPosition keyPosition;
        while (frameNumber >= 0) {
            HashMap<String, KeyPosition> map = this.keyPositions.get(Integer.valueOf(frameNumber));
            if (map != null && (keyPosition = map.get(target)) != null) {
                return keyPosition;
            }
            frameNumber--;
        }
        return null;
    }

    public KeyPosition findNextPosition(String target, int frameNumber) {
        KeyPosition keyPosition;
        while (frameNumber <= 100) {
            HashMap<String, KeyPosition> map = this.keyPositions.get(Integer.valueOf(frameNumber));
            if (map != null && (keyPosition = map.get(target)) != null) {
                return keyPosition;
            }
            frameNumber++;
        }
        return null;
    }

    public int getNumberKeyPositions(WidgetFrame frame) {
        int numKeyPositions = 0;
        for (int frameNumber = 0; frameNumber <= 100; frameNumber++) {
            HashMap<String, KeyPosition> map = this.keyPositions.get(Integer.valueOf(frameNumber));
            if (map != null) {
                KeyPosition keyPosition = map.get(frame.widget.stringId);
                if (keyPosition != null) {
                    numKeyPositions++;
                }
            }
        }
        return numKeyPositions;
    }

    public Motion getMotion(String id) {
        return getWidgetState(id, null, 0).motionControl;
    }

    public void fillKeyPositions(WidgetFrame frame, float[] x, float[] y, float[] pos) {
        KeyPosition keyPosition;
        int numKeyPositions = 0;
        for (int frameNumber = 0; frameNumber <= 100; frameNumber++) {
            HashMap<String, KeyPosition> map = this.keyPositions.get(Integer.valueOf(frameNumber));
            if (map != null && (keyPosition = map.get(frame.widget.stringId)) != null) {
                x[numKeyPositions] = keyPosition.x;
                y[numKeyPositions] = keyPosition.y;
                pos[numKeyPositions] = keyPosition.frame;
                numKeyPositions++;
            }
        }
    }

    public boolean hasPositionKeyframes() {
        return this.keyPositions.size() > 0;
    }

    public void setTransitionProperties(TypedBundle bundle) {
        bundle.applyDelta(this.mBundle);
        bundle.applyDelta(this);
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int id, int value) {
        return false;
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int id, float value) {
        if (id == 706) {
            this.mStagger = value;
            return false;
        }
        return false;
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int id, String value) {
        if (id == 705) {
            this.mDefaultInterpolatorString = value;
            this.mEasing = Easing.getInterpolator(value);
            return false;
        }
        return false;
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int id, boolean value) {
        return false;
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public int getId(String name) {
        return 0;
    }

    public boolean isEmpty() {
        return this.state.isEmpty();
    }

    public void clear() {
        this.state.clear();
    }

    public boolean contains(String key) {
        return this.state.containsKey(key);
    }

    public void addKeyPosition(String target, TypedBundle bundle) {
        getWidgetState(target, null, 0).setKeyPosition(bundle);
    }

    public void addKeyAttribute(String target, TypedBundle bundle) {
        getWidgetState(target, null, 0).setKeyAttribute(bundle);
    }

    public void addKeyCycle(String target, TypedBundle bundle) {
        getWidgetState(target, null, 0).setKeyCycle(bundle);
    }

    public void addKeyPosition(String target, int frame, int type, float x, float y) {
        TypedBundle bundle = new TypedBundle();
        bundle.add(TypedValues.PositionType.TYPE_POSITION_TYPE, 2);
        bundle.add(100, frame);
        bundle.add(TypedValues.PositionType.TYPE_PERCENT_X, x);
        bundle.add(TypedValues.PositionType.TYPE_PERCENT_Y, y);
        getWidgetState(target, null, 0).setKeyPosition(bundle);
        KeyPosition keyPosition = new KeyPosition(target, frame, type, x, y);
        HashMap<String, KeyPosition> map = this.keyPositions.get(Integer.valueOf(frame));
        if (map == null) {
            map = new HashMap<>();
            this.keyPositions.put(Integer.valueOf(frame), map);
        }
        map.put(target, keyPosition);
    }

    public void addCustomFloat(int state, String widgetId, String property, float value) {
        WidgetState widgetState = getWidgetState(widgetId, null, state);
        WidgetFrame frame = widgetState.getFrame(state);
        frame.addCustomFloat(property, value);
    }

    public void addCustomColor(int state, String widgetId, String property, int color) {
        WidgetState widgetState = getWidgetState(widgetId, null, state);
        WidgetFrame frame = widgetState.getFrame(state);
        frame.addCustomColor(property, color);
    }

    public void updateFrom(ConstraintWidgetContainer container, int state) {
        ArrayList<ConstraintWidget> children = container.getChildren();
        int count = children.size();
        for (int i = 0; i < count; i++) {
            ConstraintWidget child = children.get(i);
            WidgetState widgetState = getWidgetState(child.stringId, null, state);
            widgetState.update(child, state);
        }
    }

    public void interpolate(int parentWidth, int parentHeight, float progress) {
        Easing easing = this.mEasing;
        if (easing != null) {
            progress = (float) easing.get(progress);
        }
        for (String key : this.state.keySet()) {
            WidgetState widget = this.state.get(key);
            widget.interpolate(parentWidth, parentHeight, progress, this);
        }
    }

    public WidgetFrame getStart(String id) {
        WidgetState widgetState = this.state.get(id);
        if (widgetState == null) {
            return null;
        }
        return widgetState.start;
    }

    public WidgetFrame getEnd(String id) {
        WidgetState widgetState = this.state.get(id);
        if (widgetState == null) {
            return null;
        }
        return widgetState.end;
    }

    public WidgetFrame getInterpolated(String id) {
        WidgetState widgetState = this.state.get(id);
        if (widgetState == null) {
            return null;
        }
        return widgetState.interpolated;
    }

    public float[] getPath(String id) {
        WidgetState widgetState = this.state.get(id);
        int frames = 1000 / 16;
        float[] mPoints = new float[frames * 2];
        widgetState.motionControl.buildPath(mPoints, frames);
        return mPoints;
    }

    public int getKeyFrames(String id, float[] rectangles, int[] pathMode, int[] position) {
        WidgetState widgetState = this.state.get(id);
        return widgetState.motionControl.buildKeyFrames(rectangles, pathMode, position);
    }

    private WidgetState getWidgetState(String widgetId) {
        return this.state.get(widgetId);
    }

    private WidgetState getWidgetState(String widgetId, ConstraintWidget child, int transitionState) {
        WidgetState widgetState = this.state.get(widgetId);
        if (widgetState == null) {
            widgetState = new WidgetState();
            this.mBundle.applyDelta(widgetState.motionControl);
            this.state.put(widgetId, widgetState);
            if (child != null) {
                widgetState.update(child, transitionState);
            }
        }
        return widgetState;
    }

    public WidgetFrame getStart(ConstraintWidget child) {
        return getWidgetState(child.stringId, null, 0).start;
    }

    public WidgetFrame getEnd(ConstraintWidget child) {
        return getWidgetState(child.stringId, null, 1).end;
    }

    public WidgetFrame getInterpolated(ConstraintWidget child) {
        return getWidgetState(child.stringId, null, 2).interpolated;
    }

    public Interpolator getInterpolator() {
        return getInterpolator(this.mDefaultInterpolator, this.mDefaultInterpolatorString);
    }

    public int getAutoTransition() {
        return this.mAutoTransition;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class WidgetState {
        Motion motionControl;
        KeyCache myKeyCache = new KeyCache();
        int myParentHeight = -1;
        int myParentWidth = -1;
        WidgetFrame start = new WidgetFrame();
        WidgetFrame end = new WidgetFrame();
        WidgetFrame interpolated = new WidgetFrame();
        MotionWidget motionWidgetStart = new MotionWidget(this.start);
        MotionWidget motionWidgetEnd = new MotionWidget(this.end);
        MotionWidget motionWidgetInterpolated = new MotionWidget(this.interpolated);

        public WidgetState() {
            Motion motion = new Motion(this.motionWidgetStart);
            this.motionControl = motion;
            motion.setStart(this.motionWidgetStart);
            this.motionControl.setEnd(this.motionWidgetEnd);
        }

        public void setKeyPosition(TypedBundle prop) {
            MotionKeyPosition keyPosition = new MotionKeyPosition();
            prop.applyDelta(keyPosition);
            this.motionControl.addKey(keyPosition);
        }

        public void setKeyAttribute(TypedBundle prop) {
            MotionKeyAttributes keyAttributes = new MotionKeyAttributes();
            prop.applyDelta(keyAttributes);
            this.motionControl.addKey(keyAttributes);
        }

        public void setKeyCycle(TypedBundle prop) {
            MotionKeyCycle keyAttributes = new MotionKeyCycle();
            prop.applyDelta(keyAttributes);
            this.motionControl.addKey(keyAttributes);
        }

        public void update(ConstraintWidget child, int state) {
            if (state == 0) {
                this.start.update(child);
                this.motionControl.setStart(this.motionWidgetStart);
            } else if (state == 1) {
                this.end.update(child);
                this.motionControl.setEnd(this.motionWidgetEnd);
            }
            this.myParentWidth = -1;
        }

        public WidgetFrame getFrame(int type) {
            if (type == 0) {
                return this.start;
            }
            if (type == 1) {
                return this.end;
            }
            return this.interpolated;
        }

        public void interpolate(int parentWidth, int parentHeight, float progress, Transition transition) {
            this.myParentHeight = parentHeight;
            this.myParentWidth = parentWidth;
            this.motionControl.setup(parentWidth, parentHeight, 1.0f, System.nanoTime());
            WidgetFrame.interpolate(parentWidth, parentHeight, this.interpolated, this.start, this.end, transition, progress);
            this.interpolated.interpolatedPos = progress;
            this.motionControl.interpolate(this.motionWidgetInterpolated, progress, System.nanoTime(), this.myKeyCache);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class KeyPosition {
        int frame;
        String target;
        int type;
        float x;
        float y;

        public KeyPosition(String target, int frame, int type, float x, float y) {
            this.target = target;
            this.frame = frame;
            this.type = type;
            this.x = x;
            this.y = y;
        }
    }
}
