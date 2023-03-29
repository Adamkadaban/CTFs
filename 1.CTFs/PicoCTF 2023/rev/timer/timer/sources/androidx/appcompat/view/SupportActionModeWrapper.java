package androidx.appcompat.view;

import android.content.Context;
import android.view.ActionMode;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import androidx.appcompat.view.ActionMode;
import androidx.appcompat.view.menu.MenuItemWrapperICS;
import androidx.appcompat.view.menu.MenuWrapperICS;
import androidx.collection.SimpleArrayMap;
import androidx.core.internal.view.SupportMenu;
import androidx.core.internal.view.SupportMenuItem;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class SupportActionModeWrapper extends android.view.ActionMode {
    final Context mContext;
    final ActionMode mWrappedObject;

    public SupportActionModeWrapper(Context context, ActionMode supportActionMode) {
        this.mContext = context;
        this.mWrappedObject = supportActionMode;
    }

    @Override // android.view.ActionMode
    public Object getTag() {
        return this.mWrappedObject.getTag();
    }

    @Override // android.view.ActionMode
    public void setTag(Object tag) {
        this.mWrappedObject.setTag(tag);
    }

    @Override // android.view.ActionMode
    public void setTitle(CharSequence title) {
        this.mWrappedObject.setTitle(title);
    }

    @Override // android.view.ActionMode
    public void setSubtitle(CharSequence subtitle) {
        this.mWrappedObject.setSubtitle(subtitle);
    }

    @Override // android.view.ActionMode
    public void invalidate() {
        this.mWrappedObject.invalidate();
    }

    @Override // android.view.ActionMode
    public void finish() {
        this.mWrappedObject.finish();
    }

    @Override // android.view.ActionMode
    public Menu getMenu() {
        return new MenuWrapperICS(this.mContext, (SupportMenu) this.mWrappedObject.getMenu());
    }

    @Override // android.view.ActionMode
    public CharSequence getTitle() {
        return this.mWrappedObject.getTitle();
    }

    @Override // android.view.ActionMode
    public void setTitle(int resId) {
        this.mWrappedObject.setTitle(resId);
    }

    @Override // android.view.ActionMode
    public CharSequence getSubtitle() {
        return this.mWrappedObject.getSubtitle();
    }

    @Override // android.view.ActionMode
    public void setSubtitle(int resId) {
        this.mWrappedObject.setSubtitle(resId);
    }

    @Override // android.view.ActionMode
    public View getCustomView() {
        return this.mWrappedObject.getCustomView();
    }

    @Override // android.view.ActionMode
    public void setCustomView(View view) {
        this.mWrappedObject.setCustomView(view);
    }

    @Override // android.view.ActionMode
    public MenuInflater getMenuInflater() {
        return this.mWrappedObject.getMenuInflater();
    }

    @Override // android.view.ActionMode
    public boolean getTitleOptionalHint() {
        return this.mWrappedObject.getTitleOptionalHint();
    }

    @Override // android.view.ActionMode
    public void setTitleOptionalHint(boolean titleOptional) {
        this.mWrappedObject.setTitleOptionalHint(titleOptional);
    }

    @Override // android.view.ActionMode
    public boolean isTitleOptional() {
        return this.mWrappedObject.isTitleOptional();
    }

    /* loaded from: classes.dex */
    public static class CallbackWrapper implements ActionMode.Callback {
        final Context mContext;
        final ActionMode.Callback mWrappedCallback;
        final ArrayList<SupportActionModeWrapper> mActionModes = new ArrayList<>();
        final SimpleArrayMap<Menu, Menu> mMenus = new SimpleArrayMap<>();

        public CallbackWrapper(Context context, ActionMode.Callback supportCallback) {
            this.mContext = context;
            this.mWrappedCallback = supportCallback;
        }

        @Override // androidx.appcompat.view.ActionMode.Callback
        public boolean onCreateActionMode(ActionMode mode, Menu menu) {
            return this.mWrappedCallback.onCreateActionMode(getActionModeWrapper(mode), getMenuWrapper(menu));
        }

        @Override // androidx.appcompat.view.ActionMode.Callback
        public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
            return this.mWrappedCallback.onPrepareActionMode(getActionModeWrapper(mode), getMenuWrapper(menu));
        }

        @Override // androidx.appcompat.view.ActionMode.Callback
        public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
            return this.mWrappedCallback.onActionItemClicked(getActionModeWrapper(mode), new MenuItemWrapperICS(this.mContext, (SupportMenuItem) item));
        }

        @Override // androidx.appcompat.view.ActionMode.Callback
        public void onDestroyActionMode(ActionMode mode) {
            this.mWrappedCallback.onDestroyActionMode(getActionModeWrapper(mode));
        }

        private Menu getMenuWrapper(Menu menu) {
            Menu wrapper = this.mMenus.get(menu);
            if (wrapper == null) {
                Menu wrapper2 = new MenuWrapperICS(this.mContext, (SupportMenu) menu);
                this.mMenus.put(menu, wrapper2);
                return wrapper2;
            }
            return wrapper;
        }

        public android.view.ActionMode getActionModeWrapper(ActionMode mode) {
            int count = this.mActionModes.size();
            for (int i = 0; i < count; i++) {
                SupportActionModeWrapper wrapper = this.mActionModes.get(i);
                if (wrapper != null && wrapper.mWrappedObject == mode) {
                    return wrapper;
                }
            }
            SupportActionModeWrapper wrapper2 = new SupportActionModeWrapper(this.mContext, mode);
            this.mActionModes.add(wrapper2);
            return wrapper2;
        }
    }
}
