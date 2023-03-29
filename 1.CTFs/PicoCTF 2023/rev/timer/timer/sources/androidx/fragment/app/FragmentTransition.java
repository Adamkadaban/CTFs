package androidx.fragment.app;

import android.content.Context;
import android.graphics.Rect;
import android.os.Build;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import androidx.collection.ArrayMap;
import androidx.core.app.SharedElementCallback;
import androidx.core.os.CancellationSignal;
import androidx.core.view.OneShotPreDrawListener;
import androidx.core.view.ViewCompat;
import androidx.fragment.app.FragmentTransaction;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class FragmentTransition {
    private static final int[] INVERSE_OPS = {0, 3, 0, 1, 5, 4, 7, 6, 9, 8, 10};
    static final FragmentTransitionImpl PLATFORM_IMPL;
    static final FragmentTransitionImpl SUPPORT_IMPL;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public interface Callback {
        void onComplete(Fragment fragment, CancellationSignal cancellationSignal);

        void onStart(Fragment fragment, CancellationSignal cancellationSignal);
    }

    static {
        FragmentTransitionCompat21 fragmentTransitionCompat21;
        if (Build.VERSION.SDK_INT >= 21) {
            fragmentTransitionCompat21 = new FragmentTransitionCompat21();
        } else {
            fragmentTransitionCompat21 = null;
        }
        PLATFORM_IMPL = fragmentTransitionCompat21;
        SUPPORT_IMPL = resolveSupportImpl();
    }

    private static FragmentTransitionImpl resolveSupportImpl() {
        try {
            return (FragmentTransitionImpl) Class.forName("androidx.transition.FragmentTransitionSupport").getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
        } catch (Exception e) {
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void startTransitions(Context context, FragmentContainer fragmentContainer, ArrayList<BackStackRecord> records, ArrayList<Boolean> isRecordPop, int startIndex, int endIndex, boolean isReordered, Callback callback) {
        ViewGroup container;
        SparseArray<FragmentContainerTransition> transitioningFragments = new SparseArray<>();
        for (int i = startIndex; i < endIndex; i++) {
            BackStackRecord record = records.get(i);
            boolean isPop = isRecordPop.get(i).booleanValue();
            if (isPop) {
                calculatePopFragments(record, transitioningFragments, isReordered);
            } else {
                calculateFragments(record, transitioningFragments, isReordered);
            }
        }
        int i2 = transitioningFragments.size();
        if (i2 != 0) {
            View nonExistentView = new View(context);
            int numContainers = transitioningFragments.size();
            for (int i3 = 0; i3 < numContainers; i3++) {
                int containerId = transitioningFragments.keyAt(i3);
                ArrayMap<String, String> nameOverrides = calculateNameOverrides(containerId, records, isRecordPop, startIndex, endIndex);
                FragmentContainerTransition containerTransition = transitioningFragments.valueAt(i3);
                if (fragmentContainer.onHasView() && (container = (ViewGroup) fragmentContainer.onFindViewById(containerId)) != null) {
                    if (isReordered) {
                        configureTransitionsReordered(container, containerTransition, nonExistentView, nameOverrides, callback);
                    } else {
                        configureTransitionsOrdered(container, containerTransition, nonExistentView, nameOverrides, callback);
                    }
                }
            }
        }
    }

    private static ArrayMap<String, String> calculateNameOverrides(int containerId, ArrayList<BackStackRecord> records, ArrayList<Boolean> isRecordPop, int startIndex, int endIndex) {
        ArrayList<String> sources;
        ArrayList<String> targets;
        ArrayMap<String, String> nameOverrides = new ArrayMap<>();
        for (int recordNum = endIndex - 1; recordNum >= startIndex; recordNum--) {
            BackStackRecord record = records.get(recordNum);
            if (record.interactsWith(containerId)) {
                boolean isPop = isRecordPop.get(recordNum).booleanValue();
                if (record.mSharedElementSourceNames != null) {
                    int numSharedElements = record.mSharedElementSourceNames.size();
                    if (isPop) {
                        targets = record.mSharedElementSourceNames;
                        sources = record.mSharedElementTargetNames;
                    } else {
                        sources = record.mSharedElementSourceNames;
                        targets = record.mSharedElementTargetNames;
                    }
                    for (int i = 0; i < numSharedElements; i++) {
                        String sourceName = sources.get(i);
                        String targetName = targets.get(i);
                        String previousTarget = nameOverrides.remove(targetName);
                        if (previousTarget != null) {
                            nameOverrides.put(sourceName, previousTarget);
                        } else {
                            nameOverrides.put(sourceName, targetName);
                        }
                    }
                }
            }
        }
        return nameOverrides;
    }

    private static void configureTransitionsReordered(ViewGroup container, FragmentContainerTransition fragments, View nonExistentView, ArrayMap<String, String> nameOverrides, final Callback callback) {
        Object exitTransition;
        ArrayList<View> sharedElementsIn;
        Fragment inFragment = fragments.lastIn;
        final Fragment outFragment = fragments.firstOut;
        FragmentTransitionImpl impl = chooseImpl(outFragment, inFragment);
        if (impl == null) {
            return;
        }
        boolean inIsPop = fragments.lastInIsPop;
        boolean outIsPop = fragments.firstOutIsPop;
        ArrayList<View> sharedElementsIn2 = new ArrayList<>();
        ArrayList<View> sharedElementsOut = new ArrayList<>();
        Object enterTransition = getEnterTransition(impl, inFragment, inIsPop);
        Object exitTransition2 = getExitTransition(impl, outFragment, outIsPop);
        Object sharedElementTransition = configureSharedElementsReordered(impl, container, nonExistentView, nameOverrides, fragments, sharedElementsOut, sharedElementsIn2, enterTransition, exitTransition2);
        if (enterTransition == null && sharedElementTransition == null) {
            exitTransition = exitTransition2;
            if (exitTransition == null) {
                return;
            }
        } else {
            exitTransition = exitTransition2;
        }
        ArrayList<View> exitingViews = configureEnteringExitingViews(impl, exitTransition, outFragment, sharedElementsOut, nonExistentView);
        ArrayList<View> enteringViews = configureEnteringExitingViews(impl, enterTransition, inFragment, sharedElementsIn2, nonExistentView);
        setViewVisibility(enteringViews, 4);
        Object transition = mergeTransitions(impl, enterTransition, exitTransition, sharedElementTransition, inFragment, inIsPop);
        if (outFragment == null || exitingViews == null) {
            sharedElementsIn = sharedElementsIn2;
        } else if (exitingViews.size() > 0 || sharedElementsOut.size() > 0) {
            final CancellationSignal signal = new CancellationSignal();
            sharedElementsIn = sharedElementsIn2;
            callback.onStart(outFragment, signal);
            impl.setListenerForTransitionEnd(outFragment, transition, signal, new Runnable() { // from class: androidx.fragment.app.FragmentTransition.1
                @Override // java.lang.Runnable
                public void run() {
                    Callback.this.onComplete(outFragment, signal);
                }
            });
        } else {
            sharedElementsIn = sharedElementsIn2;
        }
        if (transition != null) {
            replaceHide(impl, exitTransition, outFragment, exitingViews);
            ArrayList<String> inNames = impl.prepareSetNameOverridesReordered(sharedElementsIn);
            ArrayList<View> sharedElementsIn3 = sharedElementsIn;
            impl.scheduleRemoveTargets(transition, enterTransition, enteringViews, exitTransition, exitingViews, sharedElementTransition, sharedElementsIn3);
            impl.beginDelayedTransition(container, transition);
            impl.setNameOverridesReordered(container, sharedElementsOut, sharedElementsIn3, inNames, nameOverrides);
            setViewVisibility(enteringViews, 0);
            impl.swapSharedElementTargets(sharedElementTransition, sharedElementsOut, sharedElementsIn3);
        }
    }

    private static void replaceHide(FragmentTransitionImpl impl, Object exitTransition, Fragment exitingFragment, final ArrayList<View> exitingViews) {
        if (exitingFragment != null && exitTransition != null && exitingFragment.mAdded && exitingFragment.mHidden && exitingFragment.mHiddenChanged) {
            exitingFragment.setHideReplaced(true);
            impl.scheduleHideFragmentView(exitTransition, exitingFragment.getView(), exitingViews);
            ViewGroup container = exitingFragment.mContainer;
            OneShotPreDrawListener.add(container, new Runnable() { // from class: androidx.fragment.app.FragmentTransition.2
                @Override // java.lang.Runnable
                public void run() {
                    FragmentTransition.setViewVisibility(exitingViews, 4);
                }
            });
        }
    }

    private static void configureTransitionsOrdered(ViewGroup container, FragmentContainerTransition fragments, View nonExistentView, ArrayMap<String, String> nameOverrides, final Callback callback) {
        Object exitTransition;
        Fragment inFragment = fragments.lastIn;
        final Fragment outFragment = fragments.firstOut;
        FragmentTransitionImpl impl = chooseImpl(outFragment, inFragment);
        if (impl == null) {
            return;
        }
        boolean inIsPop = fragments.lastInIsPop;
        boolean outIsPop = fragments.firstOutIsPop;
        Object enterTransition = getEnterTransition(impl, inFragment, inIsPop);
        Object exitTransition2 = getExitTransition(impl, outFragment, outIsPop);
        ArrayList<View> sharedElementsOut = new ArrayList<>();
        ArrayList<View> sharedElementsIn = new ArrayList<>();
        Object sharedElementTransition = configureSharedElementsOrdered(impl, container, nonExistentView, nameOverrides, fragments, sharedElementsOut, sharedElementsIn, enterTransition, exitTransition2);
        if (enterTransition == null && sharedElementTransition == null) {
            exitTransition = exitTransition2;
            if (exitTransition == null) {
                return;
            }
        } else {
            exitTransition = exitTransition2;
        }
        ArrayList<View> exitingViews = configureEnteringExitingViews(impl, exitTransition, outFragment, sharedElementsOut, nonExistentView);
        Object exitTransition3 = (exitingViews == null || exitingViews.isEmpty()) ? null : exitTransition;
        impl.addTarget(enterTransition, nonExistentView);
        Object transition = mergeTransitions(impl, enterTransition, exitTransition3, sharedElementTransition, inFragment, fragments.lastInIsPop);
        if (outFragment != null && exitingViews != null && (exitingViews.size() > 0 || sharedElementsOut.size() > 0)) {
            final CancellationSignal signal = new CancellationSignal();
            callback.onStart(outFragment, signal);
            impl.setListenerForTransitionEnd(outFragment, transition, signal, new Runnable() { // from class: androidx.fragment.app.FragmentTransition.3
                @Override // java.lang.Runnable
                public void run() {
                    Callback.this.onComplete(outFragment, signal);
                }
            });
        }
        if (transition != null) {
            ArrayList<View> enteringViews = new ArrayList<>();
            impl.scheduleRemoveTargets(transition, enterTransition, enteringViews, exitTransition3, exitingViews, sharedElementTransition, sharedElementsIn);
            scheduleTargetChange(impl, container, inFragment, nonExistentView, sharedElementsIn, enterTransition, enteringViews, exitTransition3, exitingViews);
            impl.setNameOverridesOrdered(container, sharedElementsIn, nameOverrides);
            impl.beginDelayedTransition(container, transition);
            impl.scheduleNameReset(container, sharedElementsIn, nameOverrides);
        }
    }

    private static void scheduleTargetChange(final FragmentTransitionImpl impl, ViewGroup sceneRoot, final Fragment inFragment, final View nonExistentView, final ArrayList<View> sharedElementsIn, final Object enterTransition, final ArrayList<View> enteringViews, final Object exitTransition, final ArrayList<View> exitingViews) {
        OneShotPreDrawListener.add(sceneRoot, new Runnable() { // from class: androidx.fragment.app.FragmentTransition.4
            @Override // java.lang.Runnable
            public void run() {
                Object obj = enterTransition;
                if (obj != null) {
                    impl.removeTarget(obj, nonExistentView);
                    ArrayList<View> views = FragmentTransition.configureEnteringExitingViews(impl, enterTransition, inFragment, sharedElementsIn, nonExistentView);
                    enteringViews.addAll(views);
                }
                ArrayList<View> views2 = exitingViews;
                if (views2 != null) {
                    if (exitTransition != null) {
                        ArrayList<View> tempExiting = new ArrayList<>();
                        tempExiting.add(nonExistentView);
                        impl.replaceTargets(exitTransition, exitingViews, tempExiting);
                    }
                    exitingViews.clear();
                    exitingViews.add(nonExistentView);
                }
            }
        });
    }

    private static FragmentTransitionImpl chooseImpl(Fragment outFragment, Fragment inFragment) {
        ArrayList<Object> transitions = new ArrayList<>();
        if (outFragment != null) {
            Object exitTransition = outFragment.getExitTransition();
            if (exitTransition != null) {
                transitions.add(exitTransition);
            }
            Object returnTransition = outFragment.getReturnTransition();
            if (returnTransition != null) {
                transitions.add(returnTransition);
            }
            Object sharedReturnTransition = outFragment.getSharedElementReturnTransition();
            if (sharedReturnTransition != null) {
                transitions.add(sharedReturnTransition);
            }
        }
        if (inFragment != null) {
            Object enterTransition = inFragment.getEnterTransition();
            if (enterTransition != null) {
                transitions.add(enterTransition);
            }
            Object reenterTransition = inFragment.getReenterTransition();
            if (reenterTransition != null) {
                transitions.add(reenterTransition);
            }
            Object sharedEnterTransition = inFragment.getSharedElementEnterTransition();
            if (sharedEnterTransition != null) {
                transitions.add(sharedEnterTransition);
            }
        }
        if (transitions.isEmpty()) {
            return null;
        }
        FragmentTransitionImpl fragmentTransitionImpl = PLATFORM_IMPL;
        if (fragmentTransitionImpl != null && canHandleAll(fragmentTransitionImpl, transitions)) {
            return fragmentTransitionImpl;
        }
        FragmentTransitionImpl fragmentTransitionImpl2 = SUPPORT_IMPL;
        if (fragmentTransitionImpl2 != null && canHandleAll(fragmentTransitionImpl2, transitions)) {
            return fragmentTransitionImpl2;
        }
        if (fragmentTransitionImpl == null && fragmentTransitionImpl2 == null) {
            return null;
        }
        throw new IllegalArgumentException("Invalid Transition types");
    }

    private static boolean canHandleAll(FragmentTransitionImpl impl, List<Object> transitions) {
        int size = transitions.size();
        for (int i = 0; i < size; i++) {
            if (!impl.canHandle(transitions.get(i))) {
                return false;
            }
        }
        return true;
    }

    private static Object getSharedElementTransition(FragmentTransitionImpl impl, Fragment inFragment, Fragment outFragment, boolean isPop) {
        Object sharedElementEnterTransition;
        if (inFragment == null || outFragment == null) {
            return null;
        }
        if (isPop) {
            sharedElementEnterTransition = outFragment.getSharedElementReturnTransition();
        } else {
            sharedElementEnterTransition = inFragment.getSharedElementEnterTransition();
        }
        Object transition = impl.cloneTransition(sharedElementEnterTransition);
        return impl.wrapTransitionInSet(transition);
    }

    private static Object getEnterTransition(FragmentTransitionImpl impl, Fragment inFragment, boolean isPop) {
        Object enterTransition;
        if (inFragment == null) {
            return null;
        }
        if (isPop) {
            enterTransition = inFragment.getReenterTransition();
        } else {
            enterTransition = inFragment.getEnterTransition();
        }
        return impl.cloneTransition(enterTransition);
    }

    private static Object getExitTransition(FragmentTransitionImpl impl, Fragment outFragment, boolean isPop) {
        Object exitTransition;
        if (outFragment == null) {
            return null;
        }
        if (isPop) {
            exitTransition = outFragment.getReturnTransition();
        } else {
            exitTransition = outFragment.getExitTransition();
        }
        return impl.cloneTransition(exitTransition);
    }

    private static Object configureSharedElementsReordered(final FragmentTransitionImpl impl, ViewGroup sceneRoot, View nonExistentView, ArrayMap<String, String> nameOverrides, FragmentContainerTransition fragments, ArrayList<View> sharedElementsOut, ArrayList<View> sharedElementsIn, Object enterTransition, Object exitTransition) {
        Object sharedElementTransition;
        Object sharedElementTransition2;
        Object sharedElementTransition3;
        ArrayMap<String, View> inSharedElements;
        Rect epicenter;
        View epicenterView;
        final Fragment inFragment = fragments.lastIn;
        final Fragment outFragment = fragments.firstOut;
        if (inFragment != null) {
            inFragment.requireView().setVisibility(0);
        }
        if (inFragment != null && outFragment != null) {
            final boolean inIsPop = fragments.lastInIsPop;
            if (nameOverrides.isEmpty()) {
                sharedElementTransition = null;
            } else {
                sharedElementTransition = getSharedElementTransition(impl, inFragment, outFragment, inIsPop);
            }
            ArrayMap<String, View> outSharedElements = captureOutSharedElements(impl, nameOverrides, sharedElementTransition, fragments);
            ArrayMap<String, View> inSharedElements2 = captureInSharedElements(impl, nameOverrides, sharedElementTransition, fragments);
            if (nameOverrides.isEmpty()) {
                if (outSharedElements != null) {
                    outSharedElements.clear();
                }
                if (inSharedElements2 != null) {
                    inSharedElements2.clear();
                }
                sharedElementTransition2 = null;
            } else {
                addSharedElementsWithMatchingNames(sharedElementsOut, outSharedElements, nameOverrides.keySet());
                addSharedElementsWithMatchingNames(sharedElementsIn, inSharedElements2, nameOverrides.values());
                sharedElementTransition2 = sharedElementTransition;
            }
            if (enterTransition == null && exitTransition == null && sharedElementTransition2 == null) {
                return null;
            }
            callSharedElementStartEnd(inFragment, outFragment, inIsPop, outSharedElements, true);
            if (sharedElementTransition2 != null) {
                sharedElementsIn.add(nonExistentView);
                impl.setSharedElementTargets(sharedElementTransition2, nonExistentView, sharedElementsOut);
                boolean outIsPop = fragments.firstOutIsPop;
                BackStackRecord outTransaction = fragments.firstOutTransaction;
                sharedElementTransition3 = sharedElementTransition2;
                inSharedElements = inSharedElements2;
                setOutEpicenter(impl, sharedElementTransition2, exitTransition, outSharedElements, outIsPop, outTransaction);
                Rect epicenter2 = new Rect();
                View epicenterView2 = getInEpicenterView(inSharedElements, fragments, enterTransition, inIsPop);
                if (epicenterView2 != null) {
                    impl.setEpicenter(enterTransition, epicenter2);
                }
                epicenter = epicenter2;
                epicenterView = epicenterView2;
            } else {
                sharedElementTransition3 = sharedElementTransition2;
                inSharedElements = inSharedElements2;
                epicenter = null;
                epicenterView = null;
            }
            final ArrayMap<String, View> arrayMap = inSharedElements;
            final View view = epicenterView;
            final Rect rect = epicenter;
            OneShotPreDrawListener.add(sceneRoot, new Runnable() { // from class: androidx.fragment.app.FragmentTransition.5
                @Override // java.lang.Runnable
                public void run() {
                    FragmentTransition.callSharedElementStartEnd(Fragment.this, outFragment, inIsPop, arrayMap, false);
                    View view2 = view;
                    if (view2 != null) {
                        impl.getBoundsOnScreen(view2, rect);
                    }
                }
            });
            return sharedElementTransition3;
        }
        return null;
    }

    private static void addSharedElementsWithMatchingNames(ArrayList<View> views, ArrayMap<String, View> sharedElements, Collection<String> nameOverridesSet) {
        for (int i = sharedElements.size() - 1; i >= 0; i--) {
            View view = sharedElements.valueAt(i);
            if (nameOverridesSet.contains(ViewCompat.getTransitionName(view))) {
                views.add(view);
            }
        }
    }

    private static Object configureSharedElementsOrdered(final FragmentTransitionImpl impl, ViewGroup sceneRoot, final View nonExistentView, final ArrayMap<String, String> nameOverrides, final FragmentContainerTransition fragments, final ArrayList<View> sharedElementsOut, final ArrayList<View> sharedElementsIn, final Object enterTransition, Object exitTransition) {
        Object sharedElementTransition;
        Object sharedElementTransition2;
        Rect inEpicenter;
        final Fragment inFragment = fragments.lastIn;
        final Fragment outFragment = fragments.firstOut;
        if (inFragment != null && outFragment != null) {
            final boolean inIsPop = fragments.lastInIsPop;
            if (nameOverrides.isEmpty()) {
                sharedElementTransition = null;
            } else {
                sharedElementTransition = getSharedElementTransition(impl, inFragment, outFragment, inIsPop);
            }
            ArrayMap<String, View> outSharedElements = captureOutSharedElements(impl, nameOverrides, sharedElementTransition, fragments);
            if (nameOverrides.isEmpty()) {
                sharedElementTransition2 = null;
            } else {
                sharedElementsOut.addAll(outSharedElements.values());
                sharedElementTransition2 = sharedElementTransition;
            }
            if (enterTransition == null && exitTransition == null && sharedElementTransition2 == null) {
                return null;
            }
            callSharedElementStartEnd(inFragment, outFragment, inIsPop, outSharedElements, true);
            if (sharedElementTransition2 != null) {
                Rect inEpicenter2 = new Rect();
                impl.setSharedElementTargets(sharedElementTransition2, nonExistentView, sharedElementsOut);
                boolean outIsPop = fragments.firstOutIsPop;
                BackStackRecord outTransaction = fragments.firstOutTransaction;
                setOutEpicenter(impl, sharedElementTransition2, exitTransition, outSharedElements, outIsPop, outTransaction);
                if (enterTransition != null) {
                    impl.setEpicenter(enterTransition, inEpicenter2);
                }
                inEpicenter = inEpicenter2;
            } else {
                inEpicenter = null;
            }
            final Object finalSharedElementTransition = sharedElementTransition2;
            Object sharedElementTransition3 = sharedElementTransition2;
            final Rect rect = inEpicenter;
            OneShotPreDrawListener.add(sceneRoot, new Runnable() { // from class: androidx.fragment.app.FragmentTransition.6
                @Override // java.lang.Runnable
                public void run() {
                    ArrayMap<String, View> inSharedElements = FragmentTransition.captureInSharedElements(FragmentTransitionImpl.this, nameOverrides, finalSharedElementTransition, fragments);
                    if (inSharedElements != null) {
                        sharedElementsIn.addAll(inSharedElements.values());
                        sharedElementsIn.add(nonExistentView);
                    }
                    FragmentTransition.callSharedElementStartEnd(inFragment, outFragment, inIsPop, inSharedElements, false);
                    Object obj = finalSharedElementTransition;
                    if (obj != null) {
                        FragmentTransitionImpl.this.swapSharedElementTargets(obj, sharedElementsOut, sharedElementsIn);
                        View inEpicenterView = FragmentTransition.getInEpicenterView(inSharedElements, fragments, enterTransition, inIsPop);
                        if (inEpicenterView != null) {
                            FragmentTransitionImpl.this.getBoundsOnScreen(inEpicenterView, rect);
                        }
                    }
                }
            });
            return sharedElementTransition3;
        }
        return null;
    }

    private static ArrayMap<String, View> captureOutSharedElements(FragmentTransitionImpl impl, ArrayMap<String, String> nameOverrides, Object sharedElementTransition, FragmentContainerTransition fragments) {
        SharedElementCallback sharedElementCallback;
        ArrayList<String> names;
        if (nameOverrides.isEmpty() || sharedElementTransition == null) {
            nameOverrides.clear();
            return null;
        }
        Fragment outFragment = fragments.firstOut;
        ArrayMap<String, View> outSharedElements = new ArrayMap<>();
        impl.findNamedViews(outSharedElements, outFragment.requireView());
        BackStackRecord outTransaction = fragments.firstOutTransaction;
        if (fragments.firstOutIsPop) {
            sharedElementCallback = outFragment.getEnterTransitionCallback();
            names = outTransaction.mSharedElementTargetNames;
        } else {
            sharedElementCallback = outFragment.getExitTransitionCallback();
            names = outTransaction.mSharedElementSourceNames;
        }
        if (names != null) {
            outSharedElements.retainAll(names);
        }
        if (sharedElementCallback != null) {
            sharedElementCallback.onMapSharedElements(names, outSharedElements);
            for (int i = names.size() - 1; i >= 0; i--) {
                String name = names.get(i);
                View view = outSharedElements.get(name);
                if (view == null) {
                    nameOverrides.remove(name);
                } else if (!name.equals(ViewCompat.getTransitionName(view))) {
                    String targetValue = nameOverrides.remove(name);
                    nameOverrides.put(ViewCompat.getTransitionName(view), targetValue);
                }
            }
        } else {
            nameOverrides.retainAll(outSharedElements.keySet());
        }
        return outSharedElements;
    }

    static ArrayMap<String, View> captureInSharedElements(FragmentTransitionImpl impl, ArrayMap<String, String> nameOverrides, Object sharedElementTransition, FragmentContainerTransition fragments) {
        SharedElementCallback sharedElementCallback;
        ArrayList<String> names;
        String key;
        Fragment inFragment = fragments.lastIn;
        View fragmentView = inFragment.getView();
        if (nameOverrides.isEmpty() || sharedElementTransition == null || fragmentView == null) {
            nameOverrides.clear();
            return null;
        }
        ArrayMap<String, View> inSharedElements = new ArrayMap<>();
        impl.findNamedViews(inSharedElements, fragmentView);
        BackStackRecord inTransaction = fragments.lastInTransaction;
        if (fragments.lastInIsPop) {
            sharedElementCallback = inFragment.getExitTransitionCallback();
            names = inTransaction.mSharedElementSourceNames;
        } else {
            sharedElementCallback = inFragment.getEnterTransitionCallback();
            names = inTransaction.mSharedElementTargetNames;
        }
        if (names != null) {
            inSharedElements.retainAll(names);
            inSharedElements.retainAll(nameOverrides.values());
        }
        if (sharedElementCallback != null) {
            sharedElementCallback.onMapSharedElements(names, inSharedElements);
            for (int i = names.size() - 1; i >= 0; i--) {
                String name = names.get(i);
                View view = inSharedElements.get(name);
                if (view == null) {
                    String key2 = findKeyForValue(nameOverrides, name);
                    if (key2 != null) {
                        nameOverrides.remove(key2);
                    }
                } else if (!name.equals(ViewCompat.getTransitionName(view)) && (key = findKeyForValue(nameOverrides, name)) != null) {
                    nameOverrides.put(key, ViewCompat.getTransitionName(view));
                }
            }
        } else {
            retainValues(nameOverrides, inSharedElements);
        }
        return inSharedElements;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String findKeyForValue(ArrayMap<String, String> map, String value) {
        int numElements = map.size();
        for (int i = 0; i < numElements; i++) {
            if (value.equals(map.valueAt(i))) {
                return map.keyAt(i);
            }
        }
        return null;
    }

    static View getInEpicenterView(ArrayMap<String, View> inSharedElements, FragmentContainerTransition fragments, Object enterTransition, boolean inIsPop) {
        BackStackRecord inTransaction = fragments.lastInTransaction;
        if (enterTransition != null && inSharedElements != null && inTransaction.mSharedElementSourceNames != null && !inTransaction.mSharedElementSourceNames.isEmpty()) {
            String targetName = inIsPop ? inTransaction.mSharedElementSourceNames.get(0) : inTransaction.mSharedElementTargetNames.get(0);
            return inSharedElements.get(targetName);
        }
        return null;
    }

    private static void setOutEpicenter(FragmentTransitionImpl impl, Object sharedElementTransition, Object exitTransition, ArrayMap<String, View> outSharedElements, boolean outIsPop, BackStackRecord outTransaction) {
        if (outTransaction.mSharedElementSourceNames != null && !outTransaction.mSharedElementSourceNames.isEmpty()) {
            String sourceName = outIsPop ? outTransaction.mSharedElementTargetNames.get(0) : outTransaction.mSharedElementSourceNames.get(0);
            View outEpicenterView = outSharedElements.get(sourceName);
            impl.setEpicenter(sharedElementTransition, outEpicenterView);
            if (exitTransition != null) {
                impl.setEpicenter(exitTransition, outEpicenterView);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void retainValues(ArrayMap<String, String> nameOverrides, ArrayMap<String, View> namedViews) {
        for (int i = nameOverrides.size() - 1; i >= 0; i--) {
            String targetName = nameOverrides.valueAt(i);
            if (!namedViews.containsKey(targetName)) {
                nameOverrides.removeAt(i);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void callSharedElementStartEnd(Fragment inFragment, Fragment outFragment, boolean isPop, ArrayMap<String, View> sharedElements, boolean isStart) {
        SharedElementCallback sharedElementCallback;
        if (isPop) {
            sharedElementCallback = outFragment.getEnterTransitionCallback();
        } else {
            sharedElementCallback = inFragment.getEnterTransitionCallback();
        }
        if (sharedElementCallback != null) {
            ArrayList<View> views = new ArrayList<>();
            ArrayList<String> names = new ArrayList<>();
            int count = sharedElements == null ? 0 : sharedElements.size();
            for (int i = 0; i < count; i++) {
                names.add(sharedElements.keyAt(i));
                views.add(sharedElements.valueAt(i));
            }
            if (isStart) {
                sharedElementCallback.onSharedElementStart(names, views, null);
            } else {
                sharedElementCallback.onSharedElementEnd(names, views, null);
            }
        }
    }

    static ArrayList<View> configureEnteringExitingViews(FragmentTransitionImpl impl, Object transition, Fragment fragment, ArrayList<View> sharedElements, View nonExistentView) {
        ArrayList<View> viewList = null;
        if (transition != null) {
            viewList = new ArrayList<>();
            View root = fragment.getView();
            if (root != null) {
                impl.captureTransitioningViews(viewList, root);
            }
            if (sharedElements != null) {
                viewList.removeAll(sharedElements);
            }
            if (!viewList.isEmpty()) {
                viewList.add(nonExistentView);
                impl.addTargets(transition, viewList);
            }
        }
        return viewList;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void setViewVisibility(ArrayList<View> views, int visibility) {
        if (views == null) {
            return;
        }
        for (int i = views.size() - 1; i >= 0; i--) {
            View view = views.get(i);
            view.setVisibility(visibility);
        }
    }

    private static Object mergeTransitions(FragmentTransitionImpl impl, Object enterTransition, Object exitTransition, Object sharedElementTransition, Fragment inFragment, boolean isPop) {
        boolean overlap = true;
        if (enterTransition != null && exitTransition != null && inFragment != null) {
            overlap = isPop ? inFragment.getAllowReturnTransitionOverlap() : inFragment.getAllowEnterTransitionOverlap();
        }
        if (overlap) {
            Object transition = impl.mergeTransitionsTogether(exitTransition, enterTransition, sharedElementTransition);
            return transition;
        }
        Object transition2 = impl.mergeTransitionsInSequence(exitTransition, enterTransition, sharedElementTransition);
        return transition2;
    }

    public static void calculateFragments(BackStackRecord transaction, SparseArray<FragmentContainerTransition> transitioningFragments, boolean isReordered) {
        int numOps = transaction.mOps.size();
        for (int opNum = 0; opNum < numOps; opNum++) {
            FragmentTransaction.Op op = transaction.mOps.get(opNum);
            addToFirstInLastOut(transaction, op, transitioningFragments, false, isReordered);
        }
    }

    public static void calculatePopFragments(BackStackRecord transaction, SparseArray<FragmentContainerTransition> transitioningFragments, boolean isReordered) {
        if (!transaction.mManager.getContainer().onHasView()) {
            return;
        }
        int numOps = transaction.mOps.size();
        for (int opNum = numOps - 1; opNum >= 0; opNum--) {
            FragmentTransaction.Op op = transaction.mOps.get(opNum);
            addToFirstInLastOut(transaction, op, transitioningFragments, true, isReordered);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean supportsTransition() {
        return (PLATFORM_IMPL == null && SUPPORT_IMPL == null) ? false : true;
    }

    private static void addToFirstInLastOut(BackStackRecord transaction, FragmentTransaction.Op op, SparseArray<FragmentContainerTransition> transitioningFragments, boolean isPop, boolean isReorderedTransaction) {
        int containerId;
        Fragment fragment = op.mFragment;
        if (fragment == null || (containerId = fragment.mContainerId) == 0) {
            return;
        }
        int command = isPop ? INVERSE_OPS[op.mCmd] : op.mCmd;
        boolean setLastIn = false;
        boolean wasRemoved = false;
        boolean setFirstOut = false;
        boolean wasAdded = false;
        boolean z = true;
        switch (command) {
            case 1:
            case 7:
                if (isReorderedTransaction) {
                    setLastIn = fragment.mIsNewlyAdded;
                } else {
                    setLastIn = (fragment.mAdded || fragment.mHidden) ? false : false;
                }
                wasAdded = true;
                break;
            case 3:
            case 6:
                if (isReorderedTransaction) {
                    setFirstOut = (fragment.mAdded || fragment.mView == null || fragment.mView.getVisibility() != 0 || fragment.mPostponedAlpha < 0.0f) ? false : false;
                } else {
                    setFirstOut = (!fragment.mAdded || fragment.mHidden) ? false : false;
                }
                wasRemoved = true;
                break;
            case 4:
                if (isReorderedTransaction) {
                    setFirstOut = (fragment.mHiddenChanged && fragment.mAdded && fragment.mHidden) ? false : false;
                } else {
                    setFirstOut = (!fragment.mAdded || fragment.mHidden) ? false : false;
                }
                wasRemoved = true;
                break;
            case 5:
                if (isReorderedTransaction) {
                    setLastIn = (fragment.mHiddenChanged && !fragment.mHidden && fragment.mAdded) ? false : false;
                } else {
                    setLastIn = fragment.mHidden;
                }
                wasAdded = true;
                break;
        }
        FragmentContainerTransition containerTransition = transitioningFragments.get(containerId);
        if (setLastIn) {
            containerTransition = ensureContainer(containerTransition, transitioningFragments, containerId);
            containerTransition.lastIn = fragment;
            containerTransition.lastInIsPop = isPop;
            containerTransition.lastInTransaction = transaction;
        }
        if (!isReorderedTransaction && wasAdded) {
            if (containerTransition != null && containerTransition.firstOut == fragment) {
                containerTransition.firstOut = null;
            }
            if (!transaction.mReorderingAllowed) {
                FragmentManager manager = transaction.mManager;
                FragmentStateManager fragmentStateManager = manager.createOrGetFragmentStateManager(fragment);
                manager.getFragmentStore().makeActive(fragmentStateManager);
                manager.moveToState(fragment);
            }
        }
        if (setFirstOut && (containerTransition == null || containerTransition.firstOut == null)) {
            containerTransition = ensureContainer(containerTransition, transitioningFragments, containerId);
            containerTransition.firstOut = fragment;
            containerTransition.firstOutIsPop = isPop;
            containerTransition.firstOutTransaction = transaction;
        }
        if (!isReorderedTransaction && wasRemoved && containerTransition != null && containerTransition.lastIn == fragment) {
            containerTransition.lastIn = null;
        }
    }

    private static FragmentContainerTransition ensureContainer(FragmentContainerTransition containerTransition, SparseArray<FragmentContainerTransition> transitioningFragments, int containerId) {
        if (containerTransition == null) {
            FragmentContainerTransition containerTransition2 = new FragmentContainerTransition();
            transitioningFragments.put(containerId, containerTransition2);
            return containerTransition2;
        }
        return containerTransition;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class FragmentContainerTransition {
        public Fragment firstOut;
        public boolean firstOutIsPop;
        public BackStackRecord firstOutTransaction;
        public Fragment lastIn;
        public boolean lastInIsPop;
        public BackStackRecord lastInTransaction;

        FragmentContainerTransition() {
        }
    }

    private FragmentTransition() {
    }
}
