package androidx.fragment.app;

import android.util.Log;
import android.view.ViewGroup;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class FragmentStore {
    private static final String TAG = "FragmentManager";
    private FragmentManagerViewModel mNonConfig;
    private final ArrayList<Fragment> mAdded = new ArrayList<>();
    private final HashMap<String, FragmentStateManager> mActive = new HashMap<>();

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setNonConfig(FragmentManagerViewModel nonConfig) {
        this.mNonConfig = nonConfig;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public FragmentManagerViewModel getNonConfig() {
        return this.mNonConfig;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void resetActiveFragments() {
        this.mActive.clear();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void restoreAddedFragments(List<String> added) {
        this.mAdded.clear();
        if (added != null) {
            for (String who : added) {
                Fragment f = findActiveFragment(who);
                if (f == null) {
                    throw new IllegalStateException("No instantiated fragment for (" + who + ")");
                }
                if (FragmentManager.isLoggingEnabled(2)) {
                    Log.v(TAG, "restoreSaveState: added (" + who + "): " + f);
                }
                addFragment(f);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void makeActive(FragmentStateManager newlyActive) {
        Fragment f = newlyActive.getFragment();
        if (containsActiveFragment(f.mWho)) {
            return;
        }
        this.mActive.put(f.mWho, newlyActive);
        if (f.mRetainInstanceChangedWhileDetached) {
            if (f.mRetainInstance) {
                this.mNonConfig.addRetainedFragment(f);
            } else {
                this.mNonConfig.removeRetainedFragment(f);
            }
            f.mRetainInstanceChangedWhileDetached = false;
        }
        if (FragmentManager.isLoggingEnabled(2)) {
            Log.v(TAG, "Added fragment to active set " + f);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void addFragment(Fragment fragment) {
        if (this.mAdded.contains(fragment)) {
            throw new IllegalStateException("Fragment already added: " + fragment);
        }
        synchronized (this.mAdded) {
            this.mAdded.add(fragment);
        }
        fragment.mAdded = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchStateChange(int state) {
        for (FragmentStateManager fragmentStateManager : this.mActive.values()) {
            if (fragmentStateManager != null) {
                fragmentStateManager.setFragmentManagerState(state);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void moveToExpectedState() {
        Iterator<Fragment> it = this.mAdded.iterator();
        while (it.hasNext()) {
            FragmentStateManager fragmentStateManager = this.mActive.get(it.next().mWho);
            if (fragmentStateManager != null) {
                fragmentStateManager.moveToExpectedState();
            }
        }
        for (FragmentStateManager fragmentStateManager2 : this.mActive.values()) {
            if (fragmentStateManager2 != null) {
                fragmentStateManager2.moveToExpectedState();
                Fragment f = fragmentStateManager2.getFragment();
                boolean beingRemoved = f.mRemoving && !f.isInBackStack();
                if (beingRemoved) {
                    makeInactive(fragmentStateManager2);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void removeFragment(Fragment fragment) {
        synchronized (this.mAdded) {
            this.mAdded.remove(fragment);
        }
        fragment.mAdded = false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void makeInactive(FragmentStateManager newlyInactive) {
        Fragment f = newlyInactive.getFragment();
        if (f.mRetainInstance) {
            this.mNonConfig.removeRetainedFragment(f);
        }
        FragmentStateManager removedStateManager = this.mActive.put(f.mWho, null);
        if (removedStateManager != null && FragmentManager.isLoggingEnabled(2)) {
            Log.v(TAG, "Removed fragment from active set " + f);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void burpActive() {
        Collection<FragmentStateManager> values = this.mActive.values();
        values.removeAll(Collections.singleton(null));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ArrayList<FragmentState> saveActiveFragments() {
        ArrayList<FragmentState> active = new ArrayList<>(this.mActive.size());
        for (FragmentStateManager fragmentStateManager : this.mActive.values()) {
            if (fragmentStateManager != null) {
                Fragment f = fragmentStateManager.getFragment();
                FragmentState fs = fragmentStateManager.saveState();
                active.add(fs);
                if (FragmentManager.isLoggingEnabled(2)) {
                    Log.v(TAG, "Saved state of " + f + ": " + fs.mSavedFragmentState);
                }
            }
        }
        return active;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ArrayList<String> saveAddedFragments() {
        synchronized (this.mAdded) {
            if (this.mAdded.isEmpty()) {
                return null;
            }
            ArrayList<String> added = new ArrayList<>(this.mAdded.size());
            Iterator<Fragment> it = this.mAdded.iterator();
            while (it.hasNext()) {
                Fragment f = it.next();
                added.add(f.mWho);
                if (FragmentManager.isLoggingEnabled(2)) {
                    Log.v(TAG, "saveAllState: adding fragment (" + f.mWho + "): " + f);
                }
            }
            return added;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public List<FragmentStateManager> getActiveFragmentStateManagers() {
        ArrayList<FragmentStateManager> activeFragmentStateManagers = new ArrayList<>();
        for (FragmentStateManager fragmentStateManager : this.mActive.values()) {
            if (fragmentStateManager != null) {
                activeFragmentStateManagers.add(fragmentStateManager);
            }
        }
        return activeFragmentStateManagers;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public List<Fragment> getFragments() {
        ArrayList arrayList;
        if (this.mAdded.isEmpty()) {
            return Collections.emptyList();
        }
        synchronized (this.mAdded) {
            arrayList = new ArrayList(this.mAdded);
        }
        return arrayList;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public List<Fragment> getActiveFragments() {
        ArrayList<Fragment> activeFragments = new ArrayList<>();
        for (FragmentStateManager fragmentStateManager : this.mActive.values()) {
            if (fragmentStateManager != null) {
                activeFragments.add(fragmentStateManager.getFragment());
            } else {
                activeFragments.add(null);
            }
        }
        return activeFragments;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getActiveFragmentCount() {
        return this.mActive.size();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Fragment findFragmentById(int id) {
        for (int i = this.mAdded.size() - 1; i >= 0; i--) {
            Fragment f = this.mAdded.get(i);
            if (f != null && f.mFragmentId == id) {
                return f;
            }
        }
        for (FragmentStateManager fragmentStateManager : this.mActive.values()) {
            if (fragmentStateManager != null) {
                Fragment f2 = fragmentStateManager.getFragment();
                if (f2.mFragmentId == id) {
                    return f2;
                }
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Fragment findFragmentByTag(String tag) {
        if (tag != null) {
            for (int i = this.mAdded.size() - 1; i >= 0; i--) {
                Fragment f = this.mAdded.get(i);
                if (f != null && tag.equals(f.mTag)) {
                    return f;
                }
            }
        }
        if (tag != null) {
            for (FragmentStateManager fragmentStateManager : this.mActive.values()) {
                if (fragmentStateManager != null) {
                    Fragment f2 = fragmentStateManager.getFragment();
                    if (tag.equals(f2.mTag)) {
                        return f2;
                    }
                }
            }
            return null;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean containsActiveFragment(String who) {
        return this.mActive.get(who) != null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public FragmentStateManager getFragmentStateManager(String who) {
        return this.mActive.get(who);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Fragment findFragmentByWho(String who) {
        Fragment f;
        for (FragmentStateManager fragmentStateManager : this.mActive.values()) {
            if (fragmentStateManager != null && (f = fragmentStateManager.getFragment().findFragmentByWho(who)) != null) {
                return f;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Fragment findActiveFragment(String who) {
        FragmentStateManager fragmentStateManager = this.mActive.get(who);
        if (fragmentStateManager != null) {
            return fragmentStateManager.getFragment();
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int findFragmentIndexInContainer(Fragment f) {
        ViewGroup container = f.mContainer;
        if (container == null) {
            return -1;
        }
        int fragmentIndex = this.mAdded.indexOf(f);
        for (int i = fragmentIndex - 1; i >= 0; i--) {
            Fragment underFragment = this.mAdded.get(i);
            if (underFragment.mContainer == container && underFragment.mView != null) {
                int underIndex = container.indexOfChild(underFragment.mView);
                return underIndex + 1;
            }
        }
        for (int i2 = fragmentIndex + 1; i2 < this.mAdded.size(); i2++) {
            Fragment overFragment = this.mAdded.get(i2);
            if (overFragment.mContainer == container && overFragment.mView != null) {
                return container.indexOfChild(overFragment.mView);
            }
        }
        return -1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dump(String prefix, FileDescriptor fd, PrintWriter writer, String[] args) {
        String innerPrefix = prefix + "    ";
        if (!this.mActive.isEmpty()) {
            writer.print(prefix);
            writer.println("Active Fragments:");
            for (FragmentStateManager fragmentStateManager : this.mActive.values()) {
                writer.print(prefix);
                if (fragmentStateManager != null) {
                    Fragment f = fragmentStateManager.getFragment();
                    writer.println(f);
                    f.dump(innerPrefix, fd, writer, args);
                } else {
                    writer.println("null");
                }
            }
        }
        int count = this.mAdded.size();
        if (count > 0) {
            writer.print(prefix);
            writer.println("Added Fragments:");
            for (int i = 0; i < count; i++) {
                writer.print(prefix);
                writer.print("  #");
                writer.print(i);
                writer.print(": ");
                writer.println(this.mAdded.get(i).toString());
            }
        }
    }
}
