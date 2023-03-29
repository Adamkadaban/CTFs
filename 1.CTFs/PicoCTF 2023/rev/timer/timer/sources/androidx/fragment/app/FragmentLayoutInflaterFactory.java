package androidx.fragment.app;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.fragment.R;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class FragmentLayoutInflaterFactory implements LayoutInflater.Factory2 {
    private static final String TAG = "FragmentManager";
    final FragmentManager mFragmentManager;

    /* JADX INFO: Access modifiers changed from: package-private */
    public FragmentLayoutInflaterFactory(FragmentManager fragmentManager) {
        this.mFragmentManager = fragmentManager;
    }

    @Override // android.view.LayoutInflater.Factory
    public View onCreateView(String name, Context context, AttributeSet attrs) {
        return onCreateView(null, name, context, attrs);
    }

    @Override // android.view.LayoutInflater.Factory2
    public View onCreateView(View parent, String name, Context context, AttributeSet attrs) {
        final FragmentStateManager fragmentStateManager;
        if (FragmentContainerView.class.getName().equals(name)) {
            return new FragmentContainerView(context, attrs, this.mFragmentManager);
        }
        if ("fragment".equals(name)) {
            String fname = attrs.getAttributeValue(null, "class");
            TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.Fragment);
            if (fname == null) {
                fname = a.getString(R.styleable.Fragment_android_name);
            }
            int id = a.getResourceId(R.styleable.Fragment_android_id, -1);
            String tag = a.getString(R.styleable.Fragment_android_tag);
            a.recycle();
            if (fname == null || !FragmentFactory.isFragmentClass(context.getClassLoader(), fname)) {
                return null;
            }
            int containerId = parent != null ? parent.getId() : 0;
            if (containerId != -1 || id != -1 || tag != null) {
                Fragment fragment = id != -1 ? this.mFragmentManager.findFragmentById(id) : null;
                if (fragment == null && tag != null) {
                    fragment = this.mFragmentManager.findFragmentByTag(tag);
                }
                if (fragment == null && containerId != -1) {
                    fragment = this.mFragmentManager.findFragmentById(containerId);
                }
                if (fragment == null) {
                    fragment = this.mFragmentManager.getFragmentFactory().instantiate(context.getClassLoader(), fname);
                    fragment.mFromLayout = true;
                    fragment.mFragmentId = id != 0 ? id : containerId;
                    fragment.mContainerId = containerId;
                    fragment.mTag = tag;
                    fragment.mInLayout = true;
                    fragment.mFragmentManager = this.mFragmentManager;
                    fragment.mHost = this.mFragmentManager.getHost();
                    fragment.onInflate(this.mFragmentManager.getHost().getContext(), attrs, fragment.mSavedFragmentState);
                    fragmentStateManager = this.mFragmentManager.addFragment(fragment);
                    if (FragmentManager.isLoggingEnabled(2)) {
                        Log.v(TAG, "Fragment " + fragment + " has been inflated via the <fragment> tag: id=0x" + Integer.toHexString(id));
                    }
                } else if (fragment.mInLayout) {
                    throw new IllegalArgumentException(attrs.getPositionDescription() + ": Duplicate id 0x" + Integer.toHexString(id) + ", tag " + tag + ", or parent id 0x" + Integer.toHexString(containerId) + " with another fragment for " + fname);
                } else {
                    fragment.mInLayout = true;
                    fragment.mFragmentManager = this.mFragmentManager;
                    fragment.mHost = this.mFragmentManager.getHost();
                    fragment.onInflate(this.mFragmentManager.getHost().getContext(), attrs, fragment.mSavedFragmentState);
                    fragmentStateManager = this.mFragmentManager.createOrGetFragmentStateManager(fragment);
                    if (FragmentManager.isLoggingEnabled(2)) {
                        Log.v(TAG, "Retained Fragment " + fragment + " has been re-attached via the <fragment> tag: id=0x" + Integer.toHexString(id));
                    }
                }
                fragment.mContainer = (ViewGroup) parent;
                fragmentStateManager.moveToExpectedState();
                fragmentStateManager.ensureInflatedView();
                if (fragment.mView == null) {
                    throw new IllegalStateException("Fragment " + fname + " did not create a view.");
                }
                if (id != 0) {
                    fragment.mView.setId(id);
                }
                if (fragment.mView.getTag() == null) {
                    fragment.mView.setTag(tag);
                }
                fragment.mView.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() { // from class: androidx.fragment.app.FragmentLayoutInflaterFactory.1
                    @Override // android.view.View.OnAttachStateChangeListener
                    public void onViewAttachedToWindow(View v) {
                        Fragment fragment2 = fragmentStateManager.getFragment();
                        fragmentStateManager.moveToExpectedState();
                        SpecialEffectsController controller = SpecialEffectsController.getOrCreateController((ViewGroup) fragment2.mView.getParent(), FragmentLayoutInflaterFactory.this.mFragmentManager);
                        controller.forceCompleteAllOperations();
                    }

                    @Override // android.view.View.OnAttachStateChangeListener
                    public void onViewDetachedFromWindow(View v) {
                    }
                });
                return fragment.mView;
            }
            throw new IllegalArgumentException(attrs.getPositionDescription() + ": Must specify unique android:id, android:tag, or have a parent with an id for " + fname);
        }
        return null;
    }
}
