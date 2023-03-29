package androidx.fragment.app;

import android.app.Activity;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.Log;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import androidx.core.os.EnvironmentCompat;
import androidx.core.view.ViewCompat;
import androidx.fragment.R;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.SpecialEffectsController;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.ViewModelStoreOwner;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class FragmentStateManager {
    private static final String TAG = "FragmentManager";
    private static final String TARGET_REQUEST_CODE_STATE_TAG = "android:target_req_state";
    private static final String TARGET_STATE_TAG = "android:target_state";
    private static final String USER_VISIBLE_HINT_TAG = "android:user_visible_hint";
    private static final String VIEW_REGISTRY_STATE_TAG = "android:view_registry_state";
    private static final String VIEW_STATE_TAG = "android:view_state";
    private final FragmentLifecycleCallbacksDispatcher mDispatcher;
    private final Fragment mFragment;
    private final FragmentStore mFragmentStore;
    private boolean mMovingToState = false;
    private int mFragmentManagerState = -1;

    /* JADX INFO: Access modifiers changed from: package-private */
    public FragmentStateManager(FragmentLifecycleCallbacksDispatcher dispatcher, FragmentStore fragmentStore, Fragment fragment) {
        this.mDispatcher = dispatcher;
        this.mFragmentStore = fragmentStore;
        this.mFragment = fragment;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public FragmentStateManager(FragmentLifecycleCallbacksDispatcher dispatcher, FragmentStore fragmentStore, ClassLoader classLoader, FragmentFactory fragmentFactory, FragmentState fs) {
        this.mDispatcher = dispatcher;
        this.mFragmentStore = fragmentStore;
        Fragment instantiate = fragmentFactory.instantiate(classLoader, fs.mClassName);
        this.mFragment = instantiate;
        if (fs.mArguments != null) {
            fs.mArguments.setClassLoader(classLoader);
        }
        instantiate.setArguments(fs.mArguments);
        instantiate.mWho = fs.mWho;
        instantiate.mFromLayout = fs.mFromLayout;
        instantiate.mRestored = true;
        instantiate.mFragmentId = fs.mFragmentId;
        instantiate.mContainerId = fs.mContainerId;
        instantiate.mTag = fs.mTag;
        instantiate.mRetainInstance = fs.mRetainInstance;
        instantiate.mRemoving = fs.mRemoving;
        instantiate.mDetached = fs.mDetached;
        instantiate.mHidden = fs.mHidden;
        instantiate.mMaxState = Lifecycle.State.values()[fs.mMaxLifecycleState];
        if (fs.mSavedFragmentState != null) {
            instantiate.mSavedFragmentState = fs.mSavedFragmentState;
        } else {
            instantiate.mSavedFragmentState = new Bundle();
        }
        if (FragmentManager.isLoggingEnabled(2)) {
            Log.v(TAG, "Instantiated fragment " + instantiate);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public FragmentStateManager(FragmentLifecycleCallbacksDispatcher dispatcher, FragmentStore fragmentStore, Fragment retainedFragment, FragmentState fs) {
        this.mDispatcher = dispatcher;
        this.mFragmentStore = fragmentStore;
        this.mFragment = retainedFragment;
        retainedFragment.mSavedViewState = null;
        retainedFragment.mSavedViewRegistryState = null;
        retainedFragment.mBackStackNesting = 0;
        retainedFragment.mInLayout = false;
        retainedFragment.mAdded = false;
        retainedFragment.mTargetWho = retainedFragment.mTarget != null ? retainedFragment.mTarget.mWho : null;
        retainedFragment.mTarget = null;
        if (fs.mSavedFragmentState != null) {
            retainedFragment.mSavedFragmentState = fs.mSavedFragmentState;
        } else {
            retainedFragment.mSavedFragmentState = new Bundle();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Fragment getFragment() {
        return this.mFragment;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setFragmentManagerState(int state) {
        this.mFragmentManagerState = state;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int computeExpectedState() {
        if (this.mFragment.mFragmentManager == null) {
            return this.mFragment.mState;
        }
        int maxState = this.mFragmentManagerState;
        switch (AnonymousClass2.$SwitchMap$androidx$lifecycle$Lifecycle$State[this.mFragment.mMaxState.ordinal()]) {
            case 1:
                break;
            case 2:
                maxState = Math.min(maxState, 5);
                break;
            case 3:
                maxState = Math.min(maxState, 1);
                break;
            case 4:
                maxState = Math.min(maxState, 0);
                break;
            default:
                maxState = Math.min(maxState, -1);
                break;
        }
        if (this.mFragment.mFromLayout) {
            if (this.mFragment.mInLayout) {
                maxState = Math.max(this.mFragmentManagerState, 2);
                if (this.mFragment.mView != null && this.mFragment.mView.getParent() == null) {
                    maxState = Math.min(maxState, 2);
                }
            } else {
                maxState = this.mFragmentManagerState < 4 ? Math.min(maxState, this.mFragment.mState) : Math.min(maxState, 1);
            }
        }
        if (!this.mFragment.mAdded) {
            maxState = Math.min(maxState, 1);
        }
        SpecialEffectsController.Operation.LifecycleImpact awaitingEffect = null;
        if (FragmentManager.USE_STATE_MANAGER && this.mFragment.mContainer != null) {
            SpecialEffectsController controller = SpecialEffectsController.getOrCreateController(this.mFragment.mContainer, this.mFragment.getParentFragmentManager());
            awaitingEffect = controller.getAwaitingCompletionLifecycleImpact(this);
        }
        if (awaitingEffect == SpecialEffectsController.Operation.LifecycleImpact.ADDING) {
            maxState = Math.min(maxState, 6);
        } else if (awaitingEffect == SpecialEffectsController.Operation.LifecycleImpact.REMOVING) {
            maxState = Math.max(maxState, 3);
        } else if (this.mFragment.mRemoving) {
            if (this.mFragment.isInBackStack()) {
                maxState = Math.min(maxState, 1);
            } else {
                maxState = Math.min(maxState, -1);
            }
        }
        if (this.mFragment.mDeferStart && this.mFragment.mState < 5) {
            maxState = Math.min(maxState, 4);
        }
        if (FragmentManager.isLoggingEnabled(2)) {
            Log.v(TAG, "computeExpectedState() of " + maxState + " for " + this.mFragment);
        }
        return maxState;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: androidx.fragment.app.FragmentStateManager$2  reason: invalid class name */
    /* loaded from: classes.dex */
    public static /* synthetic */ class AnonymousClass2 {
        static final /* synthetic */ int[] $SwitchMap$androidx$lifecycle$Lifecycle$State;

        static {
            int[] iArr = new int[Lifecycle.State.values().length];
            $SwitchMap$androidx$lifecycle$Lifecycle$State = iArr;
            try {
                iArr[Lifecycle.State.RESUMED.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$androidx$lifecycle$Lifecycle$State[Lifecycle.State.STARTED.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$androidx$lifecycle$Lifecycle$State[Lifecycle.State.CREATED.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$androidx$lifecycle$Lifecycle$State[Lifecycle.State.INITIALIZED.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void moveToExpectedState() {
        if (this.mMovingToState) {
            if (FragmentManager.isLoggingEnabled(2)) {
                Log.v(TAG, "Ignoring re-entrant call to moveToExpectedState() for " + getFragment());
                return;
            }
            return;
        }
        try {
            this.mMovingToState = true;
            while (true) {
                int newState = computeExpectedState();
                if (newState != this.mFragment.mState) {
                    if (newState > this.mFragment.mState) {
                        int nextStep = this.mFragment.mState + 1;
                        switch (nextStep) {
                            case 0:
                                attach();
                                break;
                            case 1:
                                create();
                                break;
                            case 2:
                                ensureInflatedView();
                                createView();
                                break;
                            case 3:
                                activityCreated();
                                break;
                            case 4:
                                if (this.mFragment.mView != null && this.mFragment.mContainer != null) {
                                    SpecialEffectsController controller = SpecialEffectsController.getOrCreateController(this.mFragment.mContainer, this.mFragment.getParentFragmentManager());
                                    int visibility = this.mFragment.mView.getVisibility();
                                    SpecialEffectsController.Operation.State finalState = SpecialEffectsController.Operation.State.from(visibility);
                                    controller.enqueueAdd(finalState, this);
                                }
                                this.mFragment.mState = 4;
                                break;
                            case 5:
                                start();
                                break;
                            case 6:
                                this.mFragment.mState = 6;
                                break;
                            case 7:
                                resume();
                                break;
                        }
                    } else {
                        int nextStep2 = this.mFragment.mState - 1;
                        switch (nextStep2) {
                            case -1:
                                detach();
                                break;
                            case 0:
                                destroy();
                                break;
                            case 1:
                                destroyFragmentView();
                                this.mFragment.mState = 1;
                                break;
                            case 2:
                                this.mFragment.mInLayout = false;
                                this.mFragment.mState = 2;
                                break;
                            case 3:
                                if (FragmentManager.isLoggingEnabled(3)) {
                                    Log.d(TAG, "movefrom ACTIVITY_CREATED: " + this.mFragment);
                                }
                                if (this.mFragment.mView != null && this.mFragment.mSavedViewState == null) {
                                    saveViewState();
                                }
                                if (this.mFragment.mView != null && this.mFragment.mContainer != null) {
                                    SpecialEffectsController.getOrCreateController(this.mFragment.mContainer, this.mFragment.getParentFragmentManager()).enqueueRemove(this);
                                }
                                this.mFragment.mState = 3;
                                break;
                            case 4:
                                stop();
                                break;
                            case 5:
                                this.mFragment.mState = 5;
                                break;
                            case 6:
                                pause();
                                break;
                        }
                    }
                } else {
                    if (FragmentManager.USE_STATE_MANAGER && this.mFragment.mHiddenChanged) {
                        if (this.mFragment.mView != null && this.mFragment.mContainer != null) {
                            SpecialEffectsController controller2 = SpecialEffectsController.getOrCreateController(this.mFragment.mContainer, this.mFragment.getParentFragmentManager());
                            if (this.mFragment.mHidden) {
                                controller2.enqueueHide(this);
                            } else {
                                controller2.enqueueShow(this);
                            }
                        }
                        if (this.mFragment.mFragmentManager != null) {
                            this.mFragment.mFragmentManager.invalidateMenuForFragment(this.mFragment);
                        }
                        this.mFragment.mHiddenChanged = false;
                        Fragment fragment = this.mFragment;
                        fragment.onHiddenChanged(fragment.mHidden);
                    }
                    return;
                }
            }
        } finally {
            this.mMovingToState = false;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void ensureInflatedView() {
        if (this.mFragment.mFromLayout && this.mFragment.mInLayout && !this.mFragment.mPerformedCreateView) {
            if (FragmentManager.isLoggingEnabled(3)) {
                Log.d(TAG, "moveto CREATE_VIEW: " + this.mFragment);
            }
            Fragment fragment = this.mFragment;
            fragment.performCreateView(fragment.performGetLayoutInflater(fragment.mSavedFragmentState), null, this.mFragment.mSavedFragmentState);
            if (this.mFragment.mView != null) {
                this.mFragment.mView.setSaveFromParentEnabled(false);
                this.mFragment.mView.setTag(R.id.fragment_container_view_tag, this.mFragment);
                if (this.mFragment.mHidden) {
                    this.mFragment.mView.setVisibility(8);
                }
                this.mFragment.performViewCreated();
                FragmentLifecycleCallbacksDispatcher fragmentLifecycleCallbacksDispatcher = this.mDispatcher;
                Fragment fragment2 = this.mFragment;
                fragmentLifecycleCallbacksDispatcher.dispatchOnFragmentViewCreated(fragment2, fragment2.mView, this.mFragment.mSavedFragmentState, false);
                this.mFragment.mState = 2;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void restoreState(ClassLoader classLoader) {
        if (this.mFragment.mSavedFragmentState == null) {
            return;
        }
        this.mFragment.mSavedFragmentState.setClassLoader(classLoader);
        Fragment fragment = this.mFragment;
        fragment.mSavedViewState = fragment.mSavedFragmentState.getSparseParcelableArray(VIEW_STATE_TAG);
        Fragment fragment2 = this.mFragment;
        fragment2.mSavedViewRegistryState = fragment2.mSavedFragmentState.getBundle(VIEW_REGISTRY_STATE_TAG);
        Fragment fragment3 = this.mFragment;
        fragment3.mTargetWho = fragment3.mSavedFragmentState.getString(TARGET_STATE_TAG);
        if (this.mFragment.mTargetWho != null) {
            Fragment fragment4 = this.mFragment;
            fragment4.mTargetRequestCode = fragment4.mSavedFragmentState.getInt(TARGET_REQUEST_CODE_STATE_TAG, 0);
        }
        if (this.mFragment.mSavedUserVisibleHint != null) {
            Fragment fragment5 = this.mFragment;
            fragment5.mUserVisibleHint = fragment5.mSavedUserVisibleHint.booleanValue();
            this.mFragment.mSavedUserVisibleHint = null;
        } else {
            Fragment fragment6 = this.mFragment;
            fragment6.mUserVisibleHint = fragment6.mSavedFragmentState.getBoolean(USER_VISIBLE_HINT_TAG, true);
        }
        if (!this.mFragment.mUserVisibleHint) {
            this.mFragment.mDeferStart = true;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void attach() {
        FragmentStateManager targetFragmentStateManager;
        if (FragmentManager.isLoggingEnabled(3)) {
            Log.d(TAG, "moveto ATTACHED: " + this.mFragment);
        }
        if (this.mFragment.mTarget != null) {
            targetFragmentStateManager = this.mFragmentStore.getFragmentStateManager(this.mFragment.mTarget.mWho);
            if (targetFragmentStateManager == null) {
                throw new IllegalStateException("Fragment " + this.mFragment + " declared target fragment " + this.mFragment.mTarget + " that does not belong to this FragmentManager!");
            }
            Fragment fragment = this.mFragment;
            fragment.mTargetWho = fragment.mTarget.mWho;
            this.mFragment.mTarget = null;
        } else if (this.mFragment.mTargetWho != null) {
            targetFragmentStateManager = this.mFragmentStore.getFragmentStateManager(this.mFragment.mTargetWho);
            if (targetFragmentStateManager == null) {
                throw new IllegalStateException("Fragment " + this.mFragment + " declared target fragment " + this.mFragment.mTargetWho + " that does not belong to this FragmentManager!");
            }
        } else {
            targetFragmentStateManager = null;
        }
        if (targetFragmentStateManager != null && (FragmentManager.USE_STATE_MANAGER || targetFragmentStateManager.getFragment().mState < 1)) {
            targetFragmentStateManager.moveToExpectedState();
        }
        Fragment fragment2 = this.mFragment;
        fragment2.mHost = fragment2.mFragmentManager.getHost();
        Fragment fragment3 = this.mFragment;
        fragment3.mParentFragment = fragment3.mFragmentManager.getParent();
        this.mDispatcher.dispatchOnFragmentPreAttached(this.mFragment, false);
        this.mFragment.performAttach();
        this.mDispatcher.dispatchOnFragmentAttached(this.mFragment, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void create() {
        if (FragmentManager.isLoggingEnabled(3)) {
            Log.d(TAG, "moveto CREATED: " + this.mFragment);
        }
        if (!this.mFragment.mIsCreated) {
            FragmentLifecycleCallbacksDispatcher fragmentLifecycleCallbacksDispatcher = this.mDispatcher;
            Fragment fragment = this.mFragment;
            fragmentLifecycleCallbacksDispatcher.dispatchOnFragmentPreCreated(fragment, fragment.mSavedFragmentState, false);
            Fragment fragment2 = this.mFragment;
            fragment2.performCreate(fragment2.mSavedFragmentState);
            FragmentLifecycleCallbacksDispatcher fragmentLifecycleCallbacksDispatcher2 = this.mDispatcher;
            Fragment fragment3 = this.mFragment;
            fragmentLifecycleCallbacksDispatcher2.dispatchOnFragmentCreated(fragment3, fragment3.mSavedFragmentState, false);
            return;
        }
        Fragment fragment4 = this.mFragment;
        fragment4.restoreChildFragmentState(fragment4.mSavedFragmentState);
        this.mFragment.mState = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void createView() {
        String resName;
        if (this.mFragment.mFromLayout) {
            return;
        }
        if (FragmentManager.isLoggingEnabled(3)) {
            Log.d(TAG, "moveto CREATE_VIEW: " + this.mFragment);
        }
        Fragment fragment = this.mFragment;
        LayoutInflater layoutInflater = fragment.performGetLayoutInflater(fragment.mSavedFragmentState);
        ViewGroup container = null;
        if (this.mFragment.mContainer != null) {
            container = this.mFragment.mContainer;
        } else if (this.mFragment.mContainerId != 0) {
            if (this.mFragment.mContainerId == -1) {
                throw new IllegalArgumentException("Cannot create fragment " + this.mFragment + " for a container view with no id");
            }
            FragmentContainer fragmentContainer = this.mFragment.mFragmentManager.getContainer();
            container = (ViewGroup) fragmentContainer.onFindViewById(this.mFragment.mContainerId);
            if (container == null && !this.mFragment.mRestored) {
                try {
                    resName = this.mFragment.getResources().getResourceName(this.mFragment.mContainerId);
                } catch (Resources.NotFoundException e) {
                    resName = EnvironmentCompat.MEDIA_UNKNOWN;
                }
                throw new IllegalArgumentException("No view found for id 0x" + Integer.toHexString(this.mFragment.mContainerId) + " (" + resName + ") for fragment " + this.mFragment);
            }
        }
        this.mFragment.mContainer = container;
        Fragment fragment2 = this.mFragment;
        fragment2.performCreateView(layoutInflater, container, fragment2.mSavedFragmentState);
        if (this.mFragment.mView != null) {
            boolean z = false;
            this.mFragment.mView.setSaveFromParentEnabled(false);
            this.mFragment.mView.setTag(R.id.fragment_container_view_tag, this.mFragment);
            if (container != null) {
                addViewToContainer();
            }
            if (this.mFragment.mHidden) {
                this.mFragment.mView.setVisibility(8);
            }
            if (ViewCompat.isAttachedToWindow(this.mFragment.mView)) {
                ViewCompat.requestApplyInsets(this.mFragment.mView);
            } else {
                final View fragmentView = this.mFragment.mView;
                fragmentView.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() { // from class: androidx.fragment.app.FragmentStateManager.1
                    @Override // android.view.View.OnAttachStateChangeListener
                    public void onViewAttachedToWindow(View v) {
                        fragmentView.removeOnAttachStateChangeListener(this);
                        ViewCompat.requestApplyInsets(fragmentView);
                    }

                    @Override // android.view.View.OnAttachStateChangeListener
                    public void onViewDetachedFromWindow(View v) {
                    }
                });
            }
            this.mFragment.performViewCreated();
            FragmentLifecycleCallbacksDispatcher fragmentLifecycleCallbacksDispatcher = this.mDispatcher;
            Fragment fragment3 = this.mFragment;
            fragmentLifecycleCallbacksDispatcher.dispatchOnFragmentViewCreated(fragment3, fragment3.mView, this.mFragment.mSavedFragmentState, false);
            int postOnViewCreatedVisibility = this.mFragment.mView.getVisibility();
            float postOnViewCreatedAlpha = this.mFragment.mView.getAlpha();
            if (FragmentManager.USE_STATE_MANAGER) {
                this.mFragment.setPostOnViewCreatedAlpha(postOnViewCreatedAlpha);
                if (this.mFragment.mContainer != null && postOnViewCreatedVisibility == 0) {
                    View focusedView = this.mFragment.mView.findFocus();
                    if (focusedView != null) {
                        this.mFragment.setFocusedView(focusedView);
                        if (FragmentManager.isLoggingEnabled(2)) {
                            Log.v(TAG, "requestFocus: Saved focused view " + focusedView + " for Fragment " + this.mFragment);
                        }
                    }
                    this.mFragment.mView.setAlpha(0.0f);
                }
            } else {
                Fragment fragment4 = this.mFragment;
                if (postOnViewCreatedVisibility == 0 && fragment4.mContainer != null) {
                    z = true;
                }
                fragment4.mIsNewlyAdded = z;
            }
        }
        this.mFragment.mState = 2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void activityCreated() {
        if (FragmentManager.isLoggingEnabled(3)) {
            Log.d(TAG, "moveto ACTIVITY_CREATED: " + this.mFragment);
        }
        Fragment fragment = this.mFragment;
        fragment.performActivityCreated(fragment.mSavedFragmentState);
        FragmentLifecycleCallbacksDispatcher fragmentLifecycleCallbacksDispatcher = this.mDispatcher;
        Fragment fragment2 = this.mFragment;
        fragmentLifecycleCallbacksDispatcher.dispatchOnFragmentActivityCreated(fragment2, fragment2.mSavedFragmentState, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void start() {
        if (FragmentManager.isLoggingEnabled(3)) {
            Log.d(TAG, "moveto STARTED: " + this.mFragment);
        }
        this.mFragment.performStart();
        this.mDispatcher.dispatchOnFragmentStarted(this.mFragment, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void resume() {
        if (FragmentManager.isLoggingEnabled(3)) {
            Log.d(TAG, "moveto RESUMED: " + this.mFragment);
        }
        View focusedView = this.mFragment.getFocusedView();
        if (focusedView != null && isFragmentViewChild(focusedView)) {
            boolean success = focusedView.requestFocus();
            if (FragmentManager.isLoggingEnabled(2)) {
                StringBuilder sb = new StringBuilder();
                sb.append("requestFocus: Restoring focused view ");
                sb.append(focusedView);
                sb.append(" ");
                sb.append(success ? "succeeded" : "failed");
                sb.append(" on Fragment ");
                sb.append(this.mFragment);
                sb.append(" resulting in focused view ");
                sb.append(this.mFragment.mView.findFocus());
                Log.v(TAG, sb.toString());
            }
        }
        this.mFragment.setFocusedView(null);
        this.mFragment.performResume();
        this.mDispatcher.dispatchOnFragmentResumed(this.mFragment, false);
        this.mFragment.mSavedFragmentState = null;
        this.mFragment.mSavedViewState = null;
        this.mFragment.mSavedViewRegistryState = null;
    }

    private boolean isFragmentViewChild(View view) {
        if (view == this.mFragment.mView) {
            return true;
        }
        for (ViewParent parent = view.getParent(); parent != null; parent = parent.getParent()) {
            if (parent == this.mFragment.mView) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void pause() {
        if (FragmentManager.isLoggingEnabled(3)) {
            Log.d(TAG, "movefrom RESUMED: " + this.mFragment);
        }
        this.mFragment.performPause();
        this.mDispatcher.dispatchOnFragmentPaused(this.mFragment, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void stop() {
        if (FragmentManager.isLoggingEnabled(3)) {
            Log.d(TAG, "movefrom STARTED: " + this.mFragment);
        }
        this.mFragment.performStop();
        this.mDispatcher.dispatchOnFragmentStopped(this.mFragment, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public FragmentState saveState() {
        FragmentState fs = new FragmentState(this.mFragment);
        if (this.mFragment.mState > -1 && fs.mSavedFragmentState == null) {
            fs.mSavedFragmentState = saveBasicState();
            if (this.mFragment.mTargetWho != null) {
                if (fs.mSavedFragmentState == null) {
                    fs.mSavedFragmentState = new Bundle();
                }
                fs.mSavedFragmentState.putString(TARGET_STATE_TAG, this.mFragment.mTargetWho);
                if (this.mFragment.mTargetRequestCode != 0) {
                    fs.mSavedFragmentState.putInt(TARGET_REQUEST_CODE_STATE_TAG, this.mFragment.mTargetRequestCode);
                }
            }
        } else {
            fs.mSavedFragmentState = this.mFragment.mSavedFragmentState;
        }
        return fs;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Fragment.SavedState saveInstanceState() {
        Bundle result;
        if (this.mFragment.mState <= -1 || (result = saveBasicState()) == null) {
            return null;
        }
        return new Fragment.SavedState(result);
    }

    private Bundle saveBasicState() {
        Bundle result = new Bundle();
        this.mFragment.performSaveInstanceState(result);
        this.mDispatcher.dispatchOnFragmentSaveInstanceState(this.mFragment, result, false);
        if (result.isEmpty()) {
            result = null;
        }
        if (this.mFragment.mView != null) {
            saveViewState();
        }
        if (this.mFragment.mSavedViewState != null) {
            if (result == null) {
                result = new Bundle();
            }
            result.putSparseParcelableArray(VIEW_STATE_TAG, this.mFragment.mSavedViewState);
        }
        if (this.mFragment.mSavedViewRegistryState != null) {
            if (result == null) {
                result = new Bundle();
            }
            result.putBundle(VIEW_REGISTRY_STATE_TAG, this.mFragment.mSavedViewRegistryState);
        }
        if (!this.mFragment.mUserVisibleHint) {
            if (result == null) {
                result = new Bundle();
            }
            result.putBoolean(USER_VISIBLE_HINT_TAG, this.mFragment.mUserVisibleHint);
        }
        return result;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void saveViewState() {
        if (this.mFragment.mView == null) {
            return;
        }
        SparseArray<Parcelable> mStateArray = new SparseArray<>();
        this.mFragment.mView.saveHierarchyState(mStateArray);
        if (mStateArray.size() > 0) {
            this.mFragment.mSavedViewState = mStateArray;
        }
        Bundle outBundle = new Bundle();
        this.mFragment.mViewLifecycleOwner.performSave(outBundle);
        if (!outBundle.isEmpty()) {
            this.mFragment.mSavedViewRegistryState = outBundle;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void destroyFragmentView() {
        if (FragmentManager.isLoggingEnabled(3)) {
            Log.d(TAG, "movefrom CREATE_VIEW: " + this.mFragment);
        }
        if (this.mFragment.mContainer != null && this.mFragment.mView != null) {
            this.mFragment.mContainer.removeView(this.mFragment.mView);
        }
        this.mFragment.performDestroyView();
        this.mDispatcher.dispatchOnFragmentViewDestroyed(this.mFragment, false);
        this.mFragment.mContainer = null;
        this.mFragment.mView = null;
        this.mFragment.mViewLifecycleOwner = null;
        this.mFragment.mViewLifecycleOwnerLiveData.setValue(null);
        this.mFragment.mInLayout = false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void destroy() {
        Fragment target;
        boolean shouldClear;
        if (FragmentManager.isLoggingEnabled(3)) {
            Log.d(TAG, "movefrom CREATED: " + this.mFragment);
        }
        boolean beingRemoved = this.mFragment.mRemoving && !this.mFragment.isInBackStack();
        boolean shouldDestroy = beingRemoved || this.mFragmentStore.getNonConfig().shouldDestroy(this.mFragment);
        if (shouldDestroy) {
            FragmentHostCallback<?> host = this.mFragment.mHost;
            if (host instanceof ViewModelStoreOwner) {
                shouldClear = this.mFragmentStore.getNonConfig().isCleared();
            } else if (host.getContext() instanceof Activity) {
                Activity activity = (Activity) host.getContext();
                shouldClear = true ^ activity.isChangingConfigurations();
            } else {
                shouldClear = true;
            }
            if (beingRemoved || shouldClear) {
                this.mFragmentStore.getNonConfig().clearNonConfigState(this.mFragment);
            }
            this.mFragment.performDestroy();
            this.mDispatcher.dispatchOnFragmentDestroyed(this.mFragment, false);
            for (FragmentStateManager fragmentStateManager : this.mFragmentStore.getActiveFragmentStateManagers()) {
                if (fragmentStateManager != null) {
                    Fragment fragment = fragmentStateManager.getFragment();
                    if (this.mFragment.mWho.equals(fragment.mTargetWho)) {
                        fragment.mTarget = this.mFragment;
                        fragment.mTargetWho = null;
                    }
                }
            }
            if (this.mFragment.mTargetWho != null) {
                Fragment fragment2 = this.mFragment;
                fragment2.mTarget = this.mFragmentStore.findActiveFragment(fragment2.mTargetWho);
            }
            this.mFragmentStore.makeInactive(this);
            return;
        }
        if (this.mFragment.mTargetWho != null && (target = this.mFragmentStore.findActiveFragment(this.mFragment.mTargetWho)) != null && target.mRetainInstance) {
            this.mFragment.mTarget = target;
        }
        this.mFragment.mState = 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void detach() {
        if (FragmentManager.isLoggingEnabled(3)) {
            Log.d(TAG, "movefrom ATTACHED: " + this.mFragment);
        }
        this.mFragment.performDetach();
        boolean z = false;
        this.mDispatcher.dispatchOnFragmentDetached(this.mFragment, false);
        this.mFragment.mState = -1;
        this.mFragment.mHost = null;
        this.mFragment.mParentFragment = null;
        this.mFragment.mFragmentManager = null;
        if (this.mFragment.mRemoving && !this.mFragment.isInBackStack()) {
            z = true;
        }
        boolean beingRemoved = z;
        if (beingRemoved || this.mFragmentStore.getNonConfig().shouldDestroy(this.mFragment)) {
            if (FragmentManager.isLoggingEnabled(3)) {
                Log.d(TAG, "initState called for fragment: " + this.mFragment);
            }
            this.mFragment.initState();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void addViewToContainer() {
        int index = this.mFragmentStore.findFragmentIndexInContainer(this.mFragment);
        this.mFragment.mContainer.addView(this.mFragment.mView, index);
    }
}
