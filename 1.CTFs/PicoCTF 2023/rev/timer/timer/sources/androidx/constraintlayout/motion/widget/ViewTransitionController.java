package androidx.constraintlayout.motion.widget;

import android.graphics.Rect;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import androidx.constraintlayout.motion.widget.ViewTransition;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.ConstraintSet;
import androidx.constraintlayout.widget.SharedValues;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
/* loaded from: classes.dex */
public class ViewTransitionController {
    ArrayList<ViewTransition.Animate> animations;
    private final MotionLayout mMotionLayout;
    private HashSet<View> mRelatedViews;
    private ArrayList<ViewTransition> viewTransitions = new ArrayList<>();
    private String TAG = "ViewTransitionController";
    ArrayList<ViewTransition.Animate> removeList = new ArrayList<>();

    public ViewTransitionController(MotionLayout layout) {
        this.mMotionLayout = layout;
    }

    public void add(ViewTransition viewTransition) {
        this.viewTransitions.add(viewTransition);
        this.mRelatedViews = null;
        if (viewTransition.getStateTransition() == 4) {
            listenForSharedVariable(viewTransition, true);
        } else if (viewTransition.getStateTransition() == 5) {
            listenForSharedVariable(viewTransition, false);
        }
    }

    void remove(int id) {
        ViewTransition del = null;
        Iterator<ViewTransition> it = this.viewTransitions.iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            ViewTransition viewTransition = it.next();
            if (viewTransition.getId() == id) {
                del = viewTransition;
                break;
            }
        }
        if (del != null) {
            this.mRelatedViews = null;
            this.viewTransitions.remove(del);
        }
    }

    private void viewTransition(ViewTransition vt, View... view) {
        int currentId = this.mMotionLayout.getCurrentState();
        if (vt.mViewTransitionMode != 2) {
            if (currentId == -1) {
                String str = this.TAG;
                Log.w(str, "No support for ViewTransition within transition yet. Currently: " + this.mMotionLayout.toString());
                return;
            }
            ConstraintSet current = this.mMotionLayout.getConstraintSet(currentId);
            if (current == null) {
                return;
            }
            vt.applyTransition(this, this.mMotionLayout, currentId, current, view);
            return;
        }
        vt.applyTransition(this, this.mMotionLayout, currentId, null, view);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void enableViewTransition(int id, boolean enable) {
        Iterator<ViewTransition> it = this.viewTransitions.iterator();
        while (it.hasNext()) {
            ViewTransition viewTransition = it.next();
            if (viewTransition.getId() == id) {
                viewTransition.setEnabled(enable);
                return;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isViewTransitionEnabled(int id) {
        Iterator<ViewTransition> it = this.viewTransitions.iterator();
        while (it.hasNext()) {
            ViewTransition viewTransition = it.next();
            if (viewTransition.getId() == id) {
                return viewTransition.isEnabled();
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void viewTransition(int id, View... views) {
        ViewTransition vt = null;
        ArrayList<View> list = new ArrayList<>();
        Iterator<ViewTransition> it = this.viewTransitions.iterator();
        while (it.hasNext()) {
            ViewTransition viewTransition = it.next();
            if (viewTransition.getId() == id) {
                vt = viewTransition;
                for (View view : views) {
                    if (viewTransition.checkTags(view)) {
                        list.add(view);
                    }
                }
                if (!list.isEmpty()) {
                    viewTransition(vt, (View[]) list.toArray(new View[0]));
                    list.clear();
                }
            }
        }
        if (vt == null) {
            Log.e(this.TAG, " Could not find ViewTransition");
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void touchEvent(MotionEvent event) {
        int currentId = this.mMotionLayout.getCurrentState();
        if (currentId == -1) {
            return;
        }
        if (this.mRelatedViews == null) {
            this.mRelatedViews = new HashSet<>();
            Iterator<ViewTransition> it = this.viewTransitions.iterator();
            while (it.hasNext()) {
                ViewTransition viewTransition = it.next();
                int count = this.mMotionLayout.getChildCount();
                for (int i = 0; i < count; i++) {
                    View view = this.mMotionLayout.getChildAt(i);
                    if (viewTransition.matchesView(view)) {
                        view.getId();
                        this.mRelatedViews.add(view);
                    }
                }
            }
        }
        float x = event.getX();
        float y = event.getY();
        Rect rec = new Rect();
        int action = event.getAction();
        ArrayList<ViewTransition.Animate> arrayList = this.animations;
        if (arrayList != null && !arrayList.isEmpty()) {
            Iterator<ViewTransition.Animate> it2 = this.animations.iterator();
            while (it2.hasNext()) {
                ViewTransition.Animate animation = it2.next();
                animation.reactTo(action, x, y);
            }
        }
        switch (action) {
            case 0:
            case 1:
                ConstraintSet current = this.mMotionLayout.getConstraintSet(currentId);
                Iterator<ViewTransition> it3 = this.viewTransitions.iterator();
                while (it3.hasNext()) {
                    ViewTransition viewTransition2 = it3.next();
                    if (viewTransition2.supports(action)) {
                        Iterator<View> it4 = this.mRelatedViews.iterator();
                        while (it4.hasNext()) {
                            View view2 = it4.next();
                            if (viewTransition2.matchesView(view2)) {
                                view2.getHitRect(rec);
                                if (rec.contains((int) x, (int) y)) {
                                    viewTransition2.applyTransition(this, this.mMotionLayout, currentId, current, view2);
                                }
                            }
                        }
                    }
                }
                return;
            default:
                return;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void addAnimation(ViewTransition.Animate animation) {
        if (this.animations == null) {
            this.animations = new ArrayList<>();
        }
        this.animations.add(animation);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void removeAnimation(ViewTransition.Animate animation) {
        this.removeList.add(animation);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void animate() {
        ArrayList<ViewTransition.Animate> arrayList = this.animations;
        if (arrayList == null) {
            return;
        }
        Iterator<ViewTransition.Animate> it = arrayList.iterator();
        while (it.hasNext()) {
            ViewTransition.Animate animation = it.next();
            animation.mutate();
        }
        this.animations.removeAll(this.removeList);
        this.removeList.clear();
        if (this.animations.isEmpty()) {
            this.animations = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void invalidate() {
        this.mMotionLayout.invalidate();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean applyViewTransition(int viewTransitionId, MotionController motionController) {
        Iterator<ViewTransition> it = this.viewTransitions.iterator();
        while (it.hasNext()) {
            ViewTransition viewTransition = it.next();
            if (viewTransition.getId() == viewTransitionId) {
                viewTransition.mKeyFrames.addAllFrames(motionController);
                return true;
            }
        }
        return false;
    }

    private void listenForSharedVariable(final ViewTransition viewTransition, final boolean isSet) {
        final int listen_for_id = viewTransition.getSharedValueID();
        final int listen_for_value = viewTransition.getSharedValue();
        ConstraintLayout.getSharedValues().addListener(viewTransition.getSharedValueID(), new SharedValues.SharedValuesListener() { // from class: androidx.constraintlayout.motion.widget.ViewTransitionController.1
            @Override // androidx.constraintlayout.widget.SharedValues.SharedValuesListener
            public void onNewValue(int id, int value, int oldValue) {
                int current_value = viewTransition.getSharedValueCurrent();
                viewTransition.setSharedValueCurrent(value);
                if (listen_for_id == id && current_value != value) {
                    if (isSet) {
                        if (listen_for_value == value) {
                            int count = ViewTransitionController.this.mMotionLayout.getChildCount();
                            for (int i = 0; i < count; i++) {
                                View view = ViewTransitionController.this.mMotionLayout.getChildAt(i);
                                if (viewTransition.matchesView(view)) {
                                    int currentId = ViewTransitionController.this.mMotionLayout.getCurrentState();
                                    ConstraintSet current = ViewTransitionController.this.mMotionLayout.getConstraintSet(currentId);
                                    ViewTransition viewTransition2 = viewTransition;
                                    ViewTransitionController viewTransitionController = ViewTransitionController.this;
                                    viewTransition2.applyTransition(viewTransitionController, viewTransitionController.mMotionLayout, currentId, current, view);
                                }
                            }
                        }
                    } else if (listen_for_value != value) {
                        int count2 = ViewTransitionController.this.mMotionLayout.getChildCount();
                        for (int i2 = 0; i2 < count2; i2++) {
                            View view2 = ViewTransitionController.this.mMotionLayout.getChildAt(i2);
                            if (viewTransition.matchesView(view2)) {
                                int currentId2 = ViewTransitionController.this.mMotionLayout.getCurrentState();
                                ConstraintSet current2 = ViewTransitionController.this.mMotionLayout.getConstraintSet(currentId2);
                                ViewTransition viewTransition3 = viewTransition;
                                ViewTransitionController viewTransitionController2 = ViewTransitionController.this;
                                viewTransition3.applyTransition(viewTransitionController2, viewTransitionController2.mMotionLayout, currentId2, current2, view2);
                            }
                        }
                    }
                }
            }
        });
    }
}
