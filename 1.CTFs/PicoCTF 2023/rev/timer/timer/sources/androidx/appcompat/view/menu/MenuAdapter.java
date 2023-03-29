package androidx.appcompat.view.menu;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import androidx.appcompat.view.menu.MenuView;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class MenuAdapter extends BaseAdapter {
    MenuBuilder mAdapterMenu;
    private int mExpandedIndex = -1;
    private boolean mForceShowIcon;
    private final LayoutInflater mInflater;
    private final int mItemLayoutRes;
    private final boolean mOverflowOnly;

    public MenuAdapter(MenuBuilder menu, LayoutInflater inflater, boolean overflowOnly, int itemLayoutRes) {
        this.mOverflowOnly = overflowOnly;
        this.mInflater = inflater;
        this.mAdapterMenu = menu;
        this.mItemLayoutRes = itemLayoutRes;
        findExpandedIndex();
    }

    public boolean getForceShowIcon() {
        return this.mForceShowIcon;
    }

    public void setForceShowIcon(boolean forceShow) {
        this.mForceShowIcon = forceShow;
    }

    @Override // android.widget.Adapter
    public int getCount() {
        ArrayList<MenuItemImpl> items = this.mOverflowOnly ? this.mAdapterMenu.getNonActionItems() : this.mAdapterMenu.getVisibleItems();
        if (this.mExpandedIndex < 0) {
            return items.size();
        }
        return items.size() - 1;
    }

    public MenuBuilder getAdapterMenu() {
        return this.mAdapterMenu;
    }

    @Override // android.widget.Adapter
    public MenuItemImpl getItem(int position) {
        ArrayList<MenuItemImpl> items = this.mOverflowOnly ? this.mAdapterMenu.getNonActionItems() : this.mAdapterMenu.getVisibleItems();
        int i = this.mExpandedIndex;
        if (i >= 0 && position >= i) {
            position++;
        }
        return items.get(position);
    }

    @Override // android.widget.Adapter
    public long getItemId(int position) {
        return position;
    }

    @Override // android.widget.Adapter
    public View getView(int position, View convertView, ViewGroup parent) {
        if (convertView == null) {
            convertView = this.mInflater.inflate(this.mItemLayoutRes, parent, false);
        }
        int currGroupId = getItem(position).getGroupId();
        int prevGroupId = position + (-1) >= 0 ? getItem(position - 1).getGroupId() : currGroupId;
        ((ListMenuItemView) convertView).setGroupDividerEnabled(this.mAdapterMenu.isGroupDividerEnabled() && currGroupId != prevGroupId);
        MenuView.ItemView itemView = (MenuView.ItemView) convertView;
        if (this.mForceShowIcon) {
            ((ListMenuItemView) convertView).setForceShowIcon(true);
        }
        itemView.initialize(getItem(position), 0);
        return convertView;
    }

    void findExpandedIndex() {
        MenuItemImpl expandedItem = this.mAdapterMenu.getExpandedItem();
        if (expandedItem != null) {
            ArrayList<MenuItemImpl> items = this.mAdapterMenu.getNonActionItems();
            int count = items.size();
            for (int i = 0; i < count; i++) {
                MenuItemImpl item = items.get(i);
                if (item == expandedItem) {
                    this.mExpandedIndex = i;
                    return;
                }
            }
        }
        this.mExpandedIndex = -1;
    }

    @Override // android.widget.BaseAdapter
    public void notifyDataSetChanged() {
        findExpandedIndex();
        super.notifyDataSetChanged();
    }
}
