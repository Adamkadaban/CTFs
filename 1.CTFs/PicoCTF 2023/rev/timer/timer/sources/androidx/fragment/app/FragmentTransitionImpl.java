package androidx.fragment.app;

import android.graphics.Rect;
import android.graphics.RectF;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import androidx.core.os.CancellationSignal;
import androidx.core.view.OneShotPreDrawListener;
import androidx.core.view.ViewCompat;
import androidx.core.view.ViewGroupCompat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
/* loaded from: classes.dex */
public abstract class FragmentTransitionImpl {
    public abstract void addTarget(Object obj, View view);

    public abstract void addTargets(Object obj, ArrayList<View> arrayList);

    public abstract void beginDelayedTransition(ViewGroup viewGroup, Object obj);

    public abstract boolean canHandle(Object obj);

    public abstract Object cloneTransition(Object obj);

    public abstract Object mergeTransitionsInSequence(Object obj, Object obj2, Object obj3);

    public abstract Object mergeTransitionsTogether(Object obj, Object obj2, Object obj3);

    public abstract void removeTarget(Object obj, View view);

    public abstract void replaceTargets(Object obj, ArrayList<View> arrayList, ArrayList<View> arrayList2);

    public abstract void scheduleHideFragmentView(Object obj, View view, ArrayList<View> arrayList);

    public abstract void scheduleRemoveTargets(Object obj, Object obj2, ArrayList<View> arrayList, Object obj3, ArrayList<View> arrayList2, Object obj4, ArrayList<View> arrayList3);

    public abstract void setEpicenter(Object obj, Rect rect);

    public abstract void setEpicenter(Object obj, View view);

    public abstract void setSharedElementTargets(Object obj, View view, ArrayList<View> arrayList);

    public abstract void swapSharedElementTargets(Object obj, ArrayList<View> arrayList, ArrayList<View> arrayList2);

    public abstract Object wrapTransitionInSet(Object obj);

    /* JADX INFO: Access modifiers changed from: protected */
    public void getBoundsOnScreen(View view, Rect epicenter) {
        if (!ViewCompat.isAttachedToWindow(view)) {
            return;
        }
        RectF rect = new RectF();
        rect.set(0.0f, 0.0f, view.getWidth(), view.getHeight());
        view.getMatrix().mapRect(rect);
        rect.offset(view.getLeft(), view.getTop());
        ViewParent parent = view.getParent();
        while (parent instanceof View) {
            View parentView = (View) parent;
            rect.offset(-parentView.getScrollX(), -parentView.getScrollY());
            parentView.getMatrix().mapRect(rect);
            rect.offset(parentView.getLeft(), parentView.getTop());
            parent = parentView.getParent();
        }
        int[] loc = new int[2];
        view.getRootView().getLocationOnScreen(loc);
        rect.offset(loc[0], loc[1]);
        epicenter.set(Math.round(rect.left), Math.round(rect.top), Math.round(rect.right), Math.round(rect.bottom));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ArrayList<String> prepareSetNameOverridesReordered(ArrayList<View> sharedElementsIn) {
        ArrayList<String> names = new ArrayList<>();
        int numSharedElements = sharedElementsIn.size();
        for (int i = 0; i < numSharedElements; i++) {
            View view = sharedElementsIn.get(i);
            names.add(ViewCompat.getTransitionName(view));
            ViewCompat.setTransitionName(view, null);
        }
        return names;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setNameOverridesReordered(View sceneRoot, final ArrayList<View> sharedElementsOut, final ArrayList<View> sharedElementsIn, final ArrayList<String> inNames, Map<String, String> nameOverrides) {
        final int numSharedElements = sharedElementsIn.size();
        final ArrayList<String> outNames = new ArrayList<>();
        for (int i = 0; i < numSharedElements; i++) {
            View view = sharedElementsOut.get(i);
            String name = ViewCompat.getTransitionName(view);
            outNames.add(name);
            if (name != null) {
                ViewCompat.setTransitionName(view, null);
                String inName = nameOverrides.get(name);
                int j = 0;
                while (true) {
                    if (j < numSharedElements) {
                        if (!inName.equals(inNames.get(j))) {
                            j++;
                        } else {
                            ViewCompat.setTransitionName(sharedElementsIn.get(j), name);
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
        }
        OneShotPreDrawListener.add(sceneRoot, new Runnable() { // from class: androidx.fragment.app.FragmentTransitionImpl.1
            @Override // java.lang.Runnable
            public void run() {
                for (int i2 = 0; i2 < numSharedElements; i2++) {
                    ViewCompat.setTransitionName((View) sharedElementsIn.get(i2), (String) inNames.get(i2));
                    ViewCompat.setTransitionName((View) sharedElementsOut.get(i2), (String) outNames.get(i2));
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void captureTransitioningViews(ArrayList<View> transitioningViews, View view) {
        if (view.getVisibility() == 0) {
            if (view instanceof ViewGroup) {
                ViewGroup viewGroup = (ViewGroup) view;
                if (ViewGroupCompat.isTransitionGroup(viewGroup)) {
                    transitioningViews.add(viewGroup);
                    return;
                }
                int count = viewGroup.getChildCount();
                for (int i = 0; i < count; i++) {
                    View child = viewGroup.getChildAt(i);
                    captureTransitioningViews(transitioningViews, child);
                }
                return;
            }
            transitioningViews.add(view);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void findNamedViews(Map<String, View> namedViews, View view) {
        if (view.getVisibility() == 0) {
            String transitionName = ViewCompat.getTransitionName(view);
            if (transitionName != null) {
                namedViews.put(transitionName, view);
            }
            if (view instanceof ViewGroup) {
                ViewGroup viewGroup = (ViewGroup) view;
                int count = viewGroup.getChildCount();
                for (int i = 0; i < count; i++) {
                    View child = viewGroup.getChildAt(i);
                    findNamedViews(namedViews, child);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setNameOverridesOrdered(View sceneRoot, final ArrayList<View> sharedElementsIn, final Map<String, String> nameOverrides) {
        OneShotPreDrawListener.add(sceneRoot, new Runnable() { // from class: androidx.fragment.app.FragmentTransitionImpl.2
            @Override // java.lang.Runnable
            public void run() {
                int numSharedElements = sharedElementsIn.size();
                for (int i = 0; i < numSharedElements; i++) {
                    View view = (View) sharedElementsIn.get(i);
                    String name = ViewCompat.getTransitionName(view);
                    if (name != null) {
                        String inName = FragmentTransitionImpl.findKeyForValue(nameOverrides, name);
                        ViewCompat.setTransitionName(view, inName);
                    }
                }
            }
        });
    }

    public void setListenerForTransitionEnd(Fragment outFragment, Object transition, CancellationSignal signal, Runnable transitionCompleteRunnable) {
        transitionCompleteRunnable.run();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void scheduleNameReset(ViewGroup sceneRoot, final ArrayList<View> sharedElementsIn, final Map<String, String> nameOverrides) {
        OneShotPreDrawListener.add(sceneRoot, new Runnable() { // from class: androidx.fragment.app.FragmentTransitionImpl.3
            @Override // java.lang.Runnable
            public void run() {
                int numSharedElements = sharedElementsIn.size();
                for (int i = 0; i < numSharedElements; i++) {
                    View view = (View) sharedElementsIn.get(i);
                    String name = ViewCompat.getTransitionName(view);
                    String inName = (String) nameOverrides.get(name);
                    ViewCompat.setTransitionName(view, inName);
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static void bfsAddViewChildren(List<View> views, View startView) {
        int startIndex = views.size();
        if (containedBeforeIndex(views, startView, startIndex)) {
            return;
        }
        if (ViewCompat.getTransitionName(startView) != null) {
            views.add(startView);
        }
        for (int index = startIndex; index < views.size(); index++) {
            View view = views.get(index);
            if (view instanceof ViewGroup) {
                ViewGroup viewGroup = (ViewGroup) view;
                int childCount = viewGroup.getChildCount();
                for (int childIndex = 0; childIndex < childCount; childIndex++) {
                    View child = viewGroup.getChildAt(childIndex);
                    if (!containedBeforeIndex(views, child, startIndex) && ViewCompat.getTransitionName(child) != null) {
                        views.add(child);
                    }
                }
            }
        }
    }

    private static boolean containedBeforeIndex(List<View> views, View view, int maxIndex) {
        for (int i = 0; i < maxIndex; i++) {
            if (views.get(i) == view) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static boolean isNullOrEmpty(List list) {
        return list == null || list.isEmpty();
    }

    static String findKeyForValue(Map<String, String> map, String value) {
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (value.equals(entry.getValue())) {
                return entry.getKey();
            }
        }
        return null;
    }
}
