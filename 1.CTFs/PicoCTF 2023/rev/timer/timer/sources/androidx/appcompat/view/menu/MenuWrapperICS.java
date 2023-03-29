package androidx.appcompat.view.menu;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.SubMenu;
import androidx.core.internal.view.SupportMenu;
/* loaded from: classes.dex */
public class MenuWrapperICS extends BaseMenuWrapper implements Menu {
    private final SupportMenu mWrappedObject;

    public MenuWrapperICS(Context context, SupportMenu object) {
        super(context);
        if (object == null) {
            throw new IllegalArgumentException("Wrapped Object can not be null.");
        }
        this.mWrappedObject = object;
    }

    @Override // android.view.Menu
    public MenuItem add(CharSequence title) {
        return getMenuItemWrapper(this.mWrappedObject.add(title));
    }

    @Override // android.view.Menu
    public MenuItem add(int titleRes) {
        return getMenuItemWrapper(this.mWrappedObject.add(titleRes));
    }

    @Override // android.view.Menu
    public MenuItem add(int groupId, int itemId, int order, CharSequence title) {
        return getMenuItemWrapper(this.mWrappedObject.add(groupId, itemId, order, title));
    }

    @Override // android.view.Menu
    public MenuItem add(int groupId, int itemId, int order, int titleRes) {
        return getMenuItemWrapper(this.mWrappedObject.add(groupId, itemId, order, titleRes));
    }

    @Override // android.view.Menu
    public SubMenu addSubMenu(CharSequence title) {
        return getSubMenuWrapper(this.mWrappedObject.addSubMenu(title));
    }

    @Override // android.view.Menu
    public SubMenu addSubMenu(int titleRes) {
        return getSubMenuWrapper(this.mWrappedObject.addSubMenu(titleRes));
    }

    @Override // android.view.Menu
    public SubMenu addSubMenu(int groupId, int itemId, int order, CharSequence title) {
        return getSubMenuWrapper(this.mWrappedObject.addSubMenu(groupId, itemId, order, title));
    }

    @Override // android.view.Menu
    public SubMenu addSubMenu(int groupId, int itemId, int order, int titleRes) {
        return getSubMenuWrapper(this.mWrappedObject.addSubMenu(groupId, itemId, order, titleRes));
    }

    @Override // android.view.Menu
    public int addIntentOptions(int groupId, int itemId, int order, ComponentName caller, Intent[] specifics, Intent intent, int flags, MenuItem[] outSpecificItems) {
        MenuItem[] items = outSpecificItems != null ? new MenuItem[outSpecificItems.length] : null;
        int result = this.mWrappedObject.addIntentOptions(groupId, itemId, order, caller, specifics, intent, flags, items);
        if (items != null) {
            int z = items.length;
            for (int i = 0; i < z; i++) {
                outSpecificItems[i] = getMenuItemWrapper(items[i]);
            }
        }
        return result;
    }

    @Override // android.view.Menu
    public void removeItem(int id) {
        internalRemoveItem(id);
        this.mWrappedObject.removeItem(id);
    }

    @Override // android.view.Menu
    public void removeGroup(int groupId) {
        internalRemoveGroup(groupId);
        this.mWrappedObject.removeGroup(groupId);
    }

    @Override // android.view.Menu
    public void clear() {
        internalClear();
        this.mWrappedObject.clear();
    }

    @Override // android.view.Menu
    public void setGroupCheckable(int group, boolean checkable, boolean exclusive) {
        this.mWrappedObject.setGroupCheckable(group, checkable, exclusive);
    }

    @Override // android.view.Menu
    public void setGroupVisible(int group, boolean visible) {
        this.mWrappedObject.setGroupVisible(group, visible);
    }

    @Override // android.view.Menu
    public void setGroupEnabled(int group, boolean enabled) {
        this.mWrappedObject.setGroupEnabled(group, enabled);
    }

    @Override // android.view.Menu
    public boolean hasVisibleItems() {
        return this.mWrappedObject.hasVisibleItems();
    }

    @Override // android.view.Menu
    public MenuItem findItem(int id) {
        return getMenuItemWrapper(this.mWrappedObject.findItem(id));
    }

    @Override // android.view.Menu
    public int size() {
        return this.mWrappedObject.size();
    }

    @Override // android.view.Menu
    public MenuItem getItem(int index) {
        return getMenuItemWrapper(this.mWrappedObject.getItem(index));
    }

    @Override // android.view.Menu
    public void close() {
        this.mWrappedObject.close();
    }

    @Override // android.view.Menu
    public boolean performShortcut(int keyCode, KeyEvent event, int flags) {
        return this.mWrappedObject.performShortcut(keyCode, event, flags);
    }

    @Override // android.view.Menu
    public boolean isShortcutKey(int keyCode, KeyEvent event) {
        return this.mWrappedObject.isShortcutKey(keyCode, event);
    }

    @Override // android.view.Menu
    public boolean performIdentifierAction(int id, int flags) {
        return this.mWrappedObject.performIdentifierAction(id, flags);
    }

    @Override // android.view.Menu
    public void setQwertyMode(boolean isQwerty) {
        this.mWrappedObject.setQwertyMode(isQwerty);
    }
}
