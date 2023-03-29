package androidx.constraintlayout.motion.widget;

import android.util.Pair;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintSet;
import java.io.PrintStream;
import java.util.HashMap;
/* loaded from: classes.dex */
public class DesignTool implements ProxyInterface {
    private static final boolean DEBUG = false;
    private static final String TAG = "DesignTool";
    static final HashMap<Pair<Integer, Integer>, String> allAttributes;
    static final HashMap<String, String> allMargins;
    private final MotionLayout mMotionLayout;
    private MotionScene mSceneCache;
    private String mLastStartState = null;
    private String mLastEndState = null;
    private int mLastStartStateId = -1;
    private int mLastEndStateId = -1;

    public DesignTool(MotionLayout motionLayout) {
        this.mMotionLayout = motionLayout;
    }

    static {
        HashMap<Pair<Integer, Integer>, String> hashMap = new HashMap<>();
        allAttributes = hashMap;
        HashMap<String, String> hashMap2 = new HashMap<>();
        allMargins = hashMap2;
        hashMap.put(Pair.create(4, 4), "layout_constraintBottom_toBottomOf");
        hashMap.put(Pair.create(4, 3), "layout_constraintBottom_toTopOf");
        hashMap.put(Pair.create(3, 4), "layout_constraintTop_toBottomOf");
        hashMap.put(Pair.create(3, 3), "layout_constraintTop_toTopOf");
        hashMap.put(Pair.create(6, 6), "layout_constraintStart_toStartOf");
        hashMap.put(Pair.create(6, 7), "layout_constraintStart_toEndOf");
        hashMap.put(Pair.create(7, 6), "layout_constraintEnd_toStartOf");
        hashMap.put(Pair.create(7, 7), "layout_constraintEnd_toEndOf");
        hashMap.put(Pair.create(1, 1), "layout_constraintLeft_toLeftOf");
        hashMap.put(Pair.create(1, 2), "layout_constraintLeft_toRightOf");
        hashMap.put(Pair.create(2, 2), "layout_constraintRight_toRightOf");
        hashMap.put(Pair.create(2, 1), "layout_constraintRight_toLeftOf");
        hashMap.put(Pair.create(5, 5), "layout_constraintBaseline_toBaselineOf");
        hashMap2.put("layout_constraintBottom_toBottomOf", "layout_marginBottom");
        hashMap2.put("layout_constraintBottom_toTopOf", "layout_marginBottom");
        hashMap2.put("layout_constraintTop_toBottomOf", "layout_marginTop");
        hashMap2.put("layout_constraintTop_toTopOf", "layout_marginTop");
        hashMap2.put("layout_constraintStart_toStartOf", "layout_marginStart");
        hashMap2.put("layout_constraintStart_toEndOf", "layout_marginStart");
        hashMap2.put("layout_constraintEnd_toStartOf", "layout_marginEnd");
        hashMap2.put("layout_constraintEnd_toEndOf", "layout_marginEnd");
        hashMap2.put("layout_constraintLeft_toLeftOf", "layout_marginLeft");
        hashMap2.put("layout_constraintLeft_toRightOf", "layout_marginLeft");
        hashMap2.put("layout_constraintRight_toRightOf", "layout_marginRight");
        hashMap2.put("layout_constraintRight_toLeftOf", "layout_marginRight");
    }

    private static int GetPxFromDp(int dpi, String value) {
        int index;
        if (value == null || (index = value.indexOf(100)) == -1) {
            return 0;
        }
        String filteredValue = value.substring(0, index);
        int dpValue = (int) ((Integer.valueOf(filteredValue).intValue() * dpi) / 160.0f);
        return dpValue;
    }

    private static void Connect(int dpi, ConstraintSet set, View view, HashMap<String, String> attributes, int from, int to) {
        String connection = allAttributes.get(Pair.create(Integer.valueOf(from), Integer.valueOf(to)));
        String connectionValue = attributes.get(connection);
        if (connectionValue != null) {
            int marginValue = 0;
            String margin = allMargins.get(connection);
            if (margin != null) {
                marginValue = GetPxFromDp(dpi, attributes.get(margin));
            }
            int id = Integer.parseInt(connectionValue);
            set.connect(view.getId(), from, id, to, marginValue);
        }
    }

    private static void SetBias(ConstraintSet set, View view, HashMap<String, String> attributes, int type) {
        String bias = "layout_constraintHorizontal_bias";
        if (type == 1) {
            bias = "layout_constraintVertical_bias";
        }
        String biasValue = attributes.get(bias);
        if (biasValue != null) {
            if (type == 0) {
                set.setHorizontalBias(view.getId(), Float.parseFloat(biasValue));
            } else if (type == 1) {
                set.setVerticalBias(view.getId(), Float.parseFloat(biasValue));
            }
        }
    }

    private static void SetDimensions(int dpi, ConstraintSet set, View view, HashMap<String, String> attributes, int type) {
        String dimension = "layout_width";
        if (type == 1) {
            dimension = "layout_height";
        }
        String dimensionValue = attributes.get(dimension);
        if (dimensionValue != null) {
            int value = -2;
            if (!dimensionValue.equalsIgnoreCase("wrap_content")) {
                value = GetPxFromDp(dpi, dimensionValue);
            }
            if (type == 0) {
                set.constrainWidth(view.getId(), value);
            } else {
                set.constrainHeight(view.getId(), value);
            }
        }
    }

    private static void SetAbsolutePositions(int dpi, ConstraintSet set, View view, HashMap<String, String> attributes) {
        String absoluteX = attributes.get("layout_editor_absoluteX");
        if (absoluteX != null) {
            set.setEditorAbsoluteX(view.getId(), GetPxFromDp(dpi, absoluteX));
        }
        String absoluteY = attributes.get("layout_editor_absoluteY");
        if (absoluteY != null) {
            set.setEditorAbsoluteY(view.getId(), GetPxFromDp(dpi, absoluteY));
        }
    }

    public int getAnimationPath(Object view, float[] path, int len) {
        if (this.mMotionLayout.mScene == null) {
            return -1;
        }
        MotionController motionController = this.mMotionLayout.mFrameArrayList.get(view);
        if (motionController == null) {
            return 0;
        }
        motionController.buildPath(path, len);
        return len;
    }

    public void getAnimationRectangles(Object view, float[] path) {
        if (this.mMotionLayout.mScene == null) {
            return;
        }
        int duration = this.mMotionLayout.mScene.getDuration();
        int frames = duration / 16;
        MotionController motionController = this.mMotionLayout.mFrameArrayList.get(view);
        if (motionController == null) {
            return;
        }
        motionController.buildRectangles(path, frames);
    }

    public int getAnimationKeyFrames(Object view, float[] key) {
        if (this.mMotionLayout.mScene == null) {
            return -1;
        }
        int duration = this.mMotionLayout.mScene.getDuration();
        int frames = duration / 16;
        MotionController motionController = this.mMotionLayout.mFrameArrayList.get(view);
        if (motionController == null) {
            return 0;
        }
        motionController.buildKeyFrames(key, null);
        return frames;
    }

    @Override // androidx.constraintlayout.motion.widget.ProxyInterface
    public void setToolPosition(float position) {
        if (this.mMotionLayout.mScene == null) {
            this.mMotionLayout.mScene = this.mSceneCache;
        }
        this.mMotionLayout.setProgress(position);
        this.mMotionLayout.evaluate(true);
        this.mMotionLayout.requestLayout();
        this.mMotionLayout.invalidate();
    }

    public void setState(String id) {
        if (id == null) {
            id = "motion_base";
        }
        if (this.mLastStartState == id) {
            return;
        }
        this.mLastStartState = id;
        this.mLastEndState = null;
        if (this.mMotionLayout.mScene == null) {
            this.mMotionLayout.mScene = this.mSceneCache;
        }
        int rscId = this.mMotionLayout.lookUpConstraintId(id);
        this.mLastStartStateId = rscId;
        if (rscId != 0) {
            if (rscId == this.mMotionLayout.getStartState()) {
                this.mMotionLayout.setProgress(0.0f);
            } else if (rscId == this.mMotionLayout.getEndState()) {
                this.mMotionLayout.setProgress(1.0f);
            } else {
                this.mMotionLayout.transitionToState(rscId);
                this.mMotionLayout.setProgress(1.0f);
            }
        }
        this.mMotionLayout.requestLayout();
    }

    public String getStartState() {
        int startId = this.mMotionLayout.getStartState();
        if (this.mLastStartStateId == startId) {
            return this.mLastStartState;
        }
        String last = this.mMotionLayout.getConstraintSetNames(startId);
        if (last != null) {
            this.mLastStartState = last;
            this.mLastStartStateId = startId;
        }
        return this.mMotionLayout.getConstraintSetNames(startId);
    }

    public String getEndState() {
        int endId = this.mMotionLayout.getEndState();
        if (this.mLastEndStateId == endId) {
            return this.mLastEndState;
        }
        String last = this.mMotionLayout.getConstraintSetNames(endId);
        if (last != null) {
            this.mLastEndState = last;
            this.mLastEndStateId = endId;
        }
        return last;
    }

    public float getProgress() {
        return this.mMotionLayout.getProgress();
    }

    public String getState() {
        if (this.mLastStartState != null && this.mLastEndState != null) {
            float progress = getProgress();
            if (progress > 0.01f) {
                if (progress >= 1.0f - 0.01f) {
                    return this.mLastEndState;
                }
            } else {
                return this.mLastStartState;
            }
        }
        return this.mLastStartState;
    }

    public boolean isInTransition() {
        return (this.mLastStartState == null || this.mLastEndState == null) ? false : true;
    }

    public void setTransition(String start, String end) {
        if (this.mMotionLayout.mScene == null) {
            this.mMotionLayout.mScene = this.mSceneCache;
        }
        int startId = this.mMotionLayout.lookUpConstraintId(start);
        int endId = this.mMotionLayout.lookUpConstraintId(end);
        this.mMotionLayout.setTransition(startId, endId);
        this.mLastStartStateId = startId;
        this.mLastEndStateId = endId;
        this.mLastStartState = start;
        this.mLastEndState = end;
    }

    public void disableAutoTransition(boolean disable) {
        this.mMotionLayout.disableAutoTransition(disable);
    }

    @Override // androidx.constraintlayout.motion.widget.ProxyInterface
    public long getTransitionTimeMs() {
        return this.mMotionLayout.getTransitionTimeMs();
    }

    public int getKeyFramePositions(Object view, int[] type, float[] pos) {
        MotionController controller = this.mMotionLayout.mFrameArrayList.get((View) view);
        if (controller == null) {
            return 0;
        }
        return controller.getKeyFramePositions(type, pos);
    }

    public int getKeyFrameInfo(Object view, int type, int[] info) {
        MotionController controller = this.mMotionLayout.mFrameArrayList.get((View) view);
        if (controller == null) {
            return 0;
        }
        return controller.getKeyFrameInfo(type, info);
    }

    @Override // androidx.constraintlayout.motion.widget.ProxyInterface
    public float getKeyFramePosition(Object view, int type, float x, float y) {
        MotionController mc;
        if ((view instanceof View) && (mc = this.mMotionLayout.mFrameArrayList.get((View) view)) != null) {
            return mc.getKeyFrameParameter(type, x, y);
        }
        return 0.0f;
    }

    @Override // androidx.constraintlayout.motion.widget.ProxyInterface
    public void setKeyFrame(Object view, int position, String name, Object value) {
        if (this.mMotionLayout.mScene != null) {
            this.mMotionLayout.mScene.setKeyframe((View) view, position, name, value);
            this.mMotionLayout.mTransitionGoalPosition = position / 100.0f;
            this.mMotionLayout.mTransitionLastPosition = 0.0f;
            this.mMotionLayout.rebuildScene();
            this.mMotionLayout.evaluate(true);
        }
    }

    @Override // androidx.constraintlayout.motion.widget.ProxyInterface
    public boolean setKeyFramePosition(Object view, int position, int type, float x, float y) {
        if ((view instanceof View) && this.mMotionLayout.mScene != null) {
            MotionController motionController = this.mMotionLayout.mFrameArrayList.get(view);
            int position2 = (int) (this.mMotionLayout.mTransitionPosition * 100.0f);
            if (motionController != null && this.mMotionLayout.mScene.hasKeyFramePosition((View) view, position2)) {
                float fx = motionController.getKeyFrameParameter(2, x, y);
                float fy = motionController.getKeyFrameParameter(5, x, y);
                this.mMotionLayout.mScene.setKeyframe((View) view, position2, "motion:percentX", Float.valueOf(fx));
                this.mMotionLayout.mScene.setKeyframe((View) view, position2, "motion:percentY", Float.valueOf(fy));
                this.mMotionLayout.rebuildScene();
                this.mMotionLayout.evaluate(true);
                this.mMotionLayout.invalidate();
                return true;
            }
        }
        return false;
    }

    public void setViewDebug(Object view, int debugMode) {
        MotionController motionController;
        if ((view instanceof View) && (motionController = this.mMotionLayout.mFrameArrayList.get(view)) != null) {
            motionController.setDrawPath(debugMode);
            this.mMotionLayout.invalidate();
        }
    }

    @Override // androidx.constraintlayout.motion.widget.ProxyInterface
    public int designAccess(int cmd, String type, Object viewObject, float[] in, int inLength, float[] out, int outLength) {
        View view = (View) viewObject;
        MotionController motionController = null;
        if (cmd != 0) {
            if (this.mMotionLayout.mScene == null || view == null) {
                return -1;
            }
            MotionController motionController2 = this.mMotionLayout.mFrameArrayList.get(view);
            motionController = motionController2;
            if (motionController == null) {
                return -1;
            }
        }
        switch (cmd) {
            case 0:
                return 1;
            case 1:
                int duration = this.mMotionLayout.mScene.getDuration();
                int frames = duration / 16;
                motionController.buildPath(out, frames);
                return frames;
            case 2:
                int duration2 = this.mMotionLayout.mScene.getDuration();
                int frames2 = duration2 / 16;
                motionController.buildKeyFrames(out, null);
                return frames2;
            case 3:
                int duration3 = this.mMotionLayout.mScene.getDuration();
                int i = duration3 / 16;
                return motionController.getAttributeValues(type, out, outLength);
            default:
                return -1;
        }
    }

    public Object getKeyframe(int type, int target, int position) {
        if (this.mMotionLayout.mScene == null) {
            return null;
        }
        return this.mMotionLayout.mScene.getKeyFrame(this.mMotionLayout.getContext(), type, target, position);
    }

    @Override // androidx.constraintlayout.motion.widget.ProxyInterface
    public Object getKeyframeAtLocation(Object viewObject, float x, float y) {
        MotionController motionController;
        View view = (View) viewObject;
        if (this.mMotionLayout.mScene == null) {
            return -1;
        }
        if (view == null || (motionController = this.mMotionLayout.mFrameArrayList.get(view)) == null) {
            return null;
        }
        ViewGroup viewGroup = (ViewGroup) view.getParent();
        int layoutWidth = viewGroup.getWidth();
        int layoutHeight = viewGroup.getHeight();
        return motionController.getPositionKeyframe(layoutWidth, layoutHeight, x, y);
    }

    @Override // androidx.constraintlayout.motion.widget.ProxyInterface
    public Boolean getPositionKeyframe(Object keyFrame, Object view, float x, float y, String[] attribute, float[] value) {
        if (keyFrame instanceof KeyPositionBase) {
            KeyPositionBase key = (KeyPositionBase) keyFrame;
            MotionController motionController = this.mMotionLayout.mFrameArrayList.get((View) view);
            motionController.positionKeyframe((View) view, key, x, y, attribute, value);
            this.mMotionLayout.rebuildScene();
            this.mMotionLayout.mInTransition = true;
            return true;
        }
        return false;
    }

    public Object getKeyframe(Object view, int type, int position) {
        if (this.mMotionLayout.mScene == null) {
            return null;
        }
        int target = ((View) view).getId();
        return this.mMotionLayout.mScene.getKeyFrame(this.mMotionLayout.getContext(), type, target, position);
    }

    public void setKeyframe(Object keyFrame, String tag, Object value) {
        if (keyFrame instanceof Key) {
            Key key = (Key) keyFrame;
            key.setValue(tag, value);
            this.mMotionLayout.rebuildScene();
            this.mMotionLayout.mInTransition = true;
        }
    }

    @Override // androidx.constraintlayout.motion.widget.ProxyInterface
    public void setAttributes(int dpi, String constraintSetId, Object opaqueView, Object opaqueAttributes) {
        View view = (View) opaqueView;
        HashMap<String, String> attributes = (HashMap) opaqueAttributes;
        int rscId = this.mMotionLayout.lookUpConstraintId(constraintSetId);
        ConstraintSet set = this.mMotionLayout.mScene.getConstraintSet(rscId);
        if (set == null) {
            return;
        }
        set.clear(view.getId());
        SetDimensions(dpi, set, view, attributes, 0);
        SetDimensions(dpi, set, view, attributes, 1);
        Connect(dpi, set, view, attributes, 6, 6);
        Connect(dpi, set, view, attributes, 6, 7);
        Connect(dpi, set, view, attributes, 7, 7);
        Connect(dpi, set, view, attributes, 7, 6);
        Connect(dpi, set, view, attributes, 1, 1);
        Connect(dpi, set, view, attributes, 1, 2);
        Connect(dpi, set, view, attributes, 2, 2);
        Connect(dpi, set, view, attributes, 2, 1);
        Connect(dpi, set, view, attributes, 3, 3);
        Connect(dpi, set, view, attributes, 3, 4);
        Connect(dpi, set, view, attributes, 4, 3);
        Connect(dpi, set, view, attributes, 4, 4);
        Connect(dpi, set, view, attributes, 5, 5);
        SetBias(set, view, attributes, 0);
        SetBias(set, view, attributes, 1);
        SetAbsolutePositions(dpi, set, view, attributes);
        this.mMotionLayout.updateState(rscId, set);
        this.mMotionLayout.requestLayout();
    }

    public void dumpConstraintSet(String set) {
        if (this.mMotionLayout.mScene == null) {
            this.mMotionLayout.mScene = this.mSceneCache;
        }
        int setId = this.mMotionLayout.lookUpConstraintId(set);
        PrintStream printStream = System.out;
        printStream.println(" dumping  " + set + " (" + setId + ")");
        try {
            this.mMotionLayout.mScene.getConstraintSet(setId).dump(this.mMotionLayout.mScene, new int[0]);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
