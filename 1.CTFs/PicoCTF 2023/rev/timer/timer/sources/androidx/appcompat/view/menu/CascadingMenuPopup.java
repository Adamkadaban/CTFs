package androidx.appcompat.view.menu;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Rect;
import android.os.Build;
import android.os.Handler;
import android.os.Parcelable;
import android.os.SystemClock;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import android.widget.HeaderViewListAdapter;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.PopupWindow;
import android.widget.TextView;
import androidx.appcompat.R;
import androidx.appcompat.view.menu.MenuPresenter;
import androidx.appcompat.widget.MenuItemHoverListener;
import androidx.appcompat.widget.MenuPopupWindow;
import androidx.core.view.GravityCompat;
import androidx.core.view.ViewCompat;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
final class CascadingMenuPopup extends MenuPopup implements MenuPresenter, View.OnKeyListener, PopupWindow.OnDismissListener {
    static final int HORIZ_POSITION_LEFT = 0;
    static final int HORIZ_POSITION_RIGHT = 1;
    private static final int ITEM_LAYOUT = R.layout.abc_cascading_menu_item_layout;
    static final int SUBMENU_TIMEOUT_MS = 200;
    private View mAnchorView;
    private final Context mContext;
    private boolean mHasXOffset;
    private boolean mHasYOffset;
    private final int mMenuMaxWidth;
    private PopupWindow.OnDismissListener mOnDismissListener;
    private final boolean mOverflowOnly;
    private final int mPopupStyleAttr;
    private final int mPopupStyleRes;
    private MenuPresenter.Callback mPresenterCallback;
    boolean mShouldCloseImmediately;
    private boolean mShowTitle;
    View mShownAnchorView;
    final Handler mSubMenuHoverHandler;
    ViewTreeObserver mTreeObserver;
    private int mXOffset;
    private int mYOffset;
    private final List<MenuBuilder> mPendingMenus = new ArrayList();
    final List<CascadingMenuInfo> mShowingMenus = new ArrayList();
    final ViewTreeObserver.OnGlobalLayoutListener mGlobalLayoutListener = new ViewTreeObserver.OnGlobalLayoutListener() { // from class: androidx.appcompat.view.menu.CascadingMenuPopup.1
        @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
        public void onGlobalLayout() {
            if (CascadingMenuPopup.this.isShowing() && CascadingMenuPopup.this.mShowingMenus.size() > 0 && !CascadingMenuPopup.this.mShowingMenus.get(0).window.isModal()) {
                View anchor = CascadingMenuPopup.this.mShownAnchorView;
                if (anchor == null || !anchor.isShown()) {
                    CascadingMenuPopup.this.dismiss();
                    return;
                }
                for (CascadingMenuInfo info : CascadingMenuPopup.this.mShowingMenus) {
                    info.window.show();
                }
            }
        }
    };
    private final View.OnAttachStateChangeListener mAttachStateChangeListener = new View.OnAttachStateChangeListener() { // from class: androidx.appcompat.view.menu.CascadingMenuPopup.2
        @Override // android.view.View.OnAttachStateChangeListener
        public void onViewAttachedToWindow(View v) {
        }

        @Override // android.view.View.OnAttachStateChangeListener
        public void onViewDetachedFromWindow(View v) {
            if (CascadingMenuPopup.this.mTreeObserver != null) {
                if (!CascadingMenuPopup.this.mTreeObserver.isAlive()) {
                    CascadingMenuPopup.this.mTreeObserver = v.getViewTreeObserver();
                }
                CascadingMenuPopup.this.mTreeObserver.removeGlobalOnLayoutListener(CascadingMenuPopup.this.mGlobalLayoutListener);
            }
            v.removeOnAttachStateChangeListener(this);
        }
    };
    private final MenuItemHoverListener mMenuItemHoverListener = new MenuItemHoverListener() { // from class: androidx.appcompat.view.menu.CascadingMenuPopup.3
        @Override // androidx.appcompat.widget.MenuItemHoverListener
        public void onItemHoverExit(MenuBuilder menu, MenuItem item) {
            CascadingMenuPopup.this.mSubMenuHoverHandler.removeCallbacksAndMessages(menu);
        }

        @Override // androidx.appcompat.widget.MenuItemHoverListener
        public void onItemHoverEnter(final MenuBuilder menu, final MenuItem item) {
            final CascadingMenuInfo nextInfo;
            CascadingMenuPopup.this.mSubMenuHoverHandler.removeCallbacksAndMessages(null);
            int menuIndex = -1;
            int i = 0;
            int count = CascadingMenuPopup.this.mShowingMenus.size();
            while (true) {
                if (i >= count) {
                    break;
                } else if (menu != CascadingMenuPopup.this.mShowingMenus.get(i).menu) {
                    i++;
                } else {
                    menuIndex = i;
                    break;
                }
            }
            if (menuIndex == -1) {
                return;
            }
            int nextIndex = menuIndex + 1;
            if (nextIndex < CascadingMenuPopup.this.mShowingMenus.size()) {
                nextInfo = CascadingMenuPopup.this.mShowingMenus.get(nextIndex);
            } else {
                nextInfo = null;
            }
            Runnable runnable = new Runnable() { // from class: androidx.appcompat.view.menu.CascadingMenuPopup.3.1
                @Override // java.lang.Runnable
                public void run() {
                    if (nextInfo != null) {
                        CascadingMenuPopup.this.mShouldCloseImmediately = true;
                        nextInfo.menu.close(false);
                        CascadingMenuPopup.this.mShouldCloseImmediately = false;
                    }
                    if (item.isEnabled() && item.hasSubMenu()) {
                        menu.performItemAction(item, 4);
                    }
                }
            };
            long uptimeMillis = SystemClock.uptimeMillis() + 200;
            CascadingMenuPopup.this.mSubMenuHoverHandler.postAtTime(runnable, menu, uptimeMillis);
        }
    };
    private int mRawDropDownGravity = 0;
    private int mDropDownGravity = 0;
    private boolean mForceShowIcon = false;
    private int mLastPosition = getInitialMenuPosition();

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface HorizPosition {
    }

    public CascadingMenuPopup(Context context, View anchor, int popupStyleAttr, int popupStyleRes, boolean overflowOnly) {
        this.mContext = context;
        this.mAnchorView = anchor;
        this.mPopupStyleAttr = popupStyleAttr;
        this.mPopupStyleRes = popupStyleRes;
        this.mOverflowOnly = overflowOnly;
        Resources res = context.getResources();
        this.mMenuMaxWidth = Math.max(res.getDisplayMetrics().widthPixels / 2, res.getDimensionPixelSize(R.dimen.abc_config_prefDialogWidth));
        this.mSubMenuHoverHandler = new Handler();
    }

    @Override // androidx.appcompat.view.menu.MenuPopup
    public void setForceShowIcon(boolean forceShow) {
        this.mForceShowIcon = forceShow;
    }

    private MenuPopupWindow createPopupWindow() {
        MenuPopupWindow popupWindow = new MenuPopupWindow(this.mContext, null, this.mPopupStyleAttr, this.mPopupStyleRes);
        popupWindow.setHoverListener(this.mMenuItemHoverListener);
        popupWindow.setOnItemClickListener(this);
        popupWindow.setOnDismissListener(this);
        popupWindow.setAnchorView(this.mAnchorView);
        popupWindow.setDropDownGravity(this.mDropDownGravity);
        popupWindow.setModal(true);
        popupWindow.setInputMethodMode(2);
        return popupWindow;
    }

    @Override // androidx.appcompat.view.menu.ShowableListMenu
    public void show() {
        if (isShowing()) {
            return;
        }
        for (MenuBuilder menu : this.mPendingMenus) {
            showMenu(menu);
        }
        this.mPendingMenus.clear();
        View view = this.mAnchorView;
        this.mShownAnchorView = view;
        if (view != null) {
            boolean addGlobalListener = this.mTreeObserver == null;
            ViewTreeObserver viewTreeObserver = view.getViewTreeObserver();
            this.mTreeObserver = viewTreeObserver;
            if (addGlobalListener) {
                viewTreeObserver.addOnGlobalLayoutListener(this.mGlobalLayoutListener);
            }
            this.mShownAnchorView.addOnAttachStateChangeListener(this.mAttachStateChangeListener);
        }
    }

    @Override // androidx.appcompat.view.menu.ShowableListMenu
    public void dismiss() {
        int length = this.mShowingMenus.size();
        if (length > 0) {
            CascadingMenuInfo[] addedMenus = (CascadingMenuInfo[]) this.mShowingMenus.toArray(new CascadingMenuInfo[length]);
            for (int i = length - 1; i >= 0; i--) {
                CascadingMenuInfo info = addedMenus[i];
                if (info.window.isShowing()) {
                    info.window.dismiss();
                }
            }
        }
    }

    @Override // android.view.View.OnKeyListener
    public boolean onKey(View v, int keyCode, KeyEvent event) {
        if (event.getAction() == 1 && keyCode == 82) {
            dismiss();
            return true;
        }
        return false;
    }

    private int getInitialMenuPosition() {
        int layoutDirection = ViewCompat.getLayoutDirection(this.mAnchorView);
        return layoutDirection == 1 ? 0 : 1;
    }

    private int getNextMenuPosition(int nextMenuWidth) {
        List<CascadingMenuInfo> list = this.mShowingMenus;
        ListView lastListView = list.get(list.size() - 1).getListView();
        int[] screenLocation = new int[2];
        lastListView.getLocationOnScreen(screenLocation);
        Rect displayFrame = new Rect();
        this.mShownAnchorView.getWindowVisibleDisplayFrame(displayFrame);
        if (this.mLastPosition == 1) {
            int right = screenLocation[0] + lastListView.getWidth() + nextMenuWidth;
            return right > displayFrame.right ? 0 : 1;
        }
        int right2 = screenLocation[0];
        int left = right2 - nextMenuWidth;
        return left < 0 ? 1 : 0;
    }

    @Override // androidx.appcompat.view.menu.MenuPopup
    public void addMenu(MenuBuilder menu) {
        menu.addMenuPresenter(this, this.mContext);
        if (isShowing()) {
            showMenu(menu);
        } else {
            this.mPendingMenus.add(menu);
        }
    }

    private void showMenu(MenuBuilder menu) {
        CascadingMenuInfo parentInfo;
        View parentView;
        int parentOffsetX;
        int parentOffsetY;
        int x;
        LayoutInflater inflater = LayoutInflater.from(this.mContext);
        MenuAdapter adapter = new MenuAdapter(menu, inflater, this.mOverflowOnly, ITEM_LAYOUT);
        if (!isShowing() && this.mForceShowIcon) {
            adapter.setForceShowIcon(true);
        } else if (isShowing()) {
            adapter.setForceShowIcon(MenuPopup.shouldPreserveIconSpacing(menu));
        }
        int menuWidth = measureIndividualMenuWidth(adapter, null, this.mContext, this.mMenuMaxWidth);
        MenuPopupWindow popupWindow = createPopupWindow();
        popupWindow.setAdapter(adapter);
        popupWindow.setContentWidth(menuWidth);
        popupWindow.setDropDownGravity(this.mDropDownGravity);
        if (this.mShowingMenus.size() > 0) {
            List<CascadingMenuInfo> list = this.mShowingMenus;
            parentInfo = list.get(list.size() - 1);
            parentView = findParentViewForSubmenu(parentInfo, menu);
        } else {
            parentInfo = null;
            parentView = null;
        }
        if (parentView != null) {
            popupWindow.setTouchModal(false);
            popupWindow.setEnterTransition(null);
            int nextMenuPosition = getNextMenuPosition(menuWidth);
            boolean showOnRight = nextMenuPosition == 1;
            this.mLastPosition = nextMenuPosition;
            if (Build.VERSION.SDK_INT >= 26) {
                popupWindow.setAnchorView(parentView);
                parentOffsetX = 0;
                parentOffsetY = 0;
            } else {
                int[] anchorScreenLocation = new int[2];
                this.mAnchorView.getLocationOnScreen(anchorScreenLocation);
                int[] parentViewScreenLocation = new int[2];
                parentView.getLocationOnScreen(parentViewScreenLocation);
                if ((this.mDropDownGravity & 7) == 5) {
                    anchorScreenLocation[0] = anchorScreenLocation[0] + this.mAnchorView.getWidth();
                    parentViewScreenLocation[0] = parentViewScreenLocation[0] + parentView.getWidth();
                }
                parentOffsetX = parentViewScreenLocation[0] - anchorScreenLocation[0];
                parentOffsetY = parentViewScreenLocation[1] - anchorScreenLocation[1];
            }
            if ((this.mDropDownGravity & 5) == 5) {
                if (showOnRight) {
                    x = parentOffsetX + menuWidth;
                } else {
                    int x2 = parentView.getWidth();
                    x = parentOffsetX - x2;
                }
            } else if (showOnRight) {
                x = parentView.getWidth() + parentOffsetX;
            } else {
                x = parentOffsetX - menuWidth;
            }
            popupWindow.setHorizontalOffset(x);
            popupWindow.setOverlapAnchor(true);
            popupWindow.setVerticalOffset(parentOffsetY);
        } else {
            if (this.mHasXOffset) {
                popupWindow.setHorizontalOffset(this.mXOffset);
            }
            if (this.mHasYOffset) {
                popupWindow.setVerticalOffset(this.mYOffset);
            }
            Rect epicenterBounds = getEpicenterBounds();
            popupWindow.setEpicenterBounds(epicenterBounds);
        }
        CascadingMenuInfo menuInfo = new CascadingMenuInfo(popupWindow, menu, this.mLastPosition);
        this.mShowingMenus.add(menuInfo);
        popupWindow.show();
        ListView listView = popupWindow.getListView();
        listView.setOnKeyListener(this);
        if (parentInfo == null && this.mShowTitle && menu.getHeaderTitle() != null) {
            FrameLayout titleItemView = (FrameLayout) inflater.inflate(R.layout.abc_popup_menu_header_item_layout, (ViewGroup) listView, false);
            TextView titleView = (TextView) titleItemView.findViewById(16908310);
            titleItemView.setEnabled(false);
            titleView.setText(menu.getHeaderTitle());
            listView.addHeaderView(titleItemView, null, false);
            popupWindow.show();
        }
    }

    private MenuItem findMenuItemForSubmenu(MenuBuilder parent, MenuBuilder submenu) {
        int count = parent.size();
        for (int i = 0; i < count; i++) {
            MenuItem item = parent.getItem(i);
            if (item.hasSubMenu() && submenu == item.getSubMenu()) {
                return item;
            }
        }
        return null;
    }

    private View findParentViewForSubmenu(CascadingMenuInfo parentInfo, MenuBuilder submenu) {
        int headersCount;
        MenuAdapter menuAdapter;
        int ownerViewPosition;
        MenuItem owner = findMenuItemForSubmenu(parentInfo.menu, submenu);
        if (owner == null) {
            return null;
        }
        ListView listView = parentInfo.getListView();
        ListAdapter listAdapter = listView.getAdapter();
        if (listAdapter instanceof HeaderViewListAdapter) {
            HeaderViewListAdapter headerAdapter = (HeaderViewListAdapter) listAdapter;
            headersCount = headerAdapter.getHeadersCount();
            menuAdapter = (MenuAdapter) headerAdapter.getWrappedAdapter();
        } else {
            headersCount = 0;
            menuAdapter = (MenuAdapter) listAdapter;
        }
        int ownerPosition = -1;
        int i = 0;
        int count = menuAdapter.getCount();
        while (true) {
            if (i >= count) {
                break;
            } else if (owner != menuAdapter.getItem(i)) {
                i++;
            } else {
                ownerPosition = i;
                break;
            }
        }
        if (ownerPosition == -1 || (ownerViewPosition = (ownerPosition + headersCount) - listView.getFirstVisiblePosition()) < 0 || ownerViewPosition >= listView.getChildCount()) {
            return null;
        }
        return listView.getChildAt(ownerViewPosition);
    }

    @Override // androidx.appcompat.view.menu.ShowableListMenu
    public boolean isShowing() {
        return this.mShowingMenus.size() > 0 && this.mShowingMenus.get(0).window.isShowing();
    }

    @Override // android.widget.PopupWindow.OnDismissListener
    public void onDismiss() {
        CascadingMenuInfo dismissedInfo = null;
        int i = 0;
        int count = this.mShowingMenus.size();
        while (true) {
            if (i >= count) {
                break;
            }
            CascadingMenuInfo info = this.mShowingMenus.get(i);
            if (info.window.isShowing()) {
                i++;
            } else {
                dismissedInfo = info;
                break;
            }
        }
        if (dismissedInfo != null) {
            dismissedInfo.menu.close(false);
        }
    }

    @Override // androidx.appcompat.view.menu.MenuPresenter
    public void updateMenuView(boolean cleared) {
        for (CascadingMenuInfo info : this.mShowingMenus) {
            toMenuAdapter(info.getListView().getAdapter()).notifyDataSetChanged();
        }
    }

    @Override // androidx.appcompat.view.menu.MenuPresenter
    public void setCallback(MenuPresenter.Callback cb) {
        this.mPresenterCallback = cb;
    }

    @Override // androidx.appcompat.view.menu.MenuPresenter
    public boolean onSubMenuSelected(SubMenuBuilder subMenu) {
        for (CascadingMenuInfo info : this.mShowingMenus) {
            if (subMenu == info.menu) {
                info.getListView().requestFocus();
                return true;
            }
        }
        if (subMenu.hasVisibleItems()) {
            addMenu(subMenu);
            MenuPresenter.Callback callback = this.mPresenterCallback;
            if (callback != null) {
                callback.onOpenSubMenu(subMenu);
            }
            return true;
        }
        return false;
    }

    private int findIndexOfAddedMenu(MenuBuilder menu) {
        int count = this.mShowingMenus.size();
        for (int i = 0; i < count; i++) {
            CascadingMenuInfo info = this.mShowingMenus.get(i);
            if (menu == info.menu) {
                return i;
            }
        }
        return -1;
    }

    @Override // androidx.appcompat.view.menu.MenuPresenter
    public void onCloseMenu(MenuBuilder menu, boolean allMenusAreClosing) {
        int menuIndex = findIndexOfAddedMenu(menu);
        if (menuIndex < 0) {
            return;
        }
        int nextMenuIndex = menuIndex + 1;
        if (nextMenuIndex < this.mShowingMenus.size()) {
            CascadingMenuInfo childInfo = this.mShowingMenus.get(nextMenuIndex);
            childInfo.menu.close(false);
        }
        CascadingMenuInfo info = this.mShowingMenus.remove(menuIndex);
        info.menu.removeMenuPresenter(this);
        if (this.mShouldCloseImmediately) {
            info.window.setExitTransition(null);
            info.window.setAnimationStyle(0);
        }
        info.window.dismiss();
        int count = this.mShowingMenus.size();
        if (count > 0) {
            this.mLastPosition = this.mShowingMenus.get(count - 1).position;
        } else {
            this.mLastPosition = getInitialMenuPosition();
        }
        if (count == 0) {
            dismiss();
            MenuPresenter.Callback callback = this.mPresenterCallback;
            if (callback != null) {
                callback.onCloseMenu(menu, true);
            }
            ViewTreeObserver viewTreeObserver = this.mTreeObserver;
            if (viewTreeObserver != null) {
                if (viewTreeObserver.isAlive()) {
                    this.mTreeObserver.removeGlobalOnLayoutListener(this.mGlobalLayoutListener);
                }
                this.mTreeObserver = null;
            }
            this.mShownAnchorView.removeOnAttachStateChangeListener(this.mAttachStateChangeListener);
            this.mOnDismissListener.onDismiss();
        } else if (allMenusAreClosing) {
            CascadingMenuInfo rootInfo = this.mShowingMenus.get(0);
            rootInfo.menu.close(false);
        }
    }

    @Override // androidx.appcompat.view.menu.MenuPresenter
    public boolean flagActionItems() {
        return false;
    }

    @Override // androidx.appcompat.view.menu.MenuPresenter
    public Parcelable onSaveInstanceState() {
        return null;
    }

    @Override // androidx.appcompat.view.menu.MenuPresenter
    public void onRestoreInstanceState(Parcelable state) {
    }

    @Override // androidx.appcompat.view.menu.MenuPopup
    public void setGravity(int dropDownGravity) {
        if (this.mRawDropDownGravity != dropDownGravity) {
            this.mRawDropDownGravity = dropDownGravity;
            this.mDropDownGravity = GravityCompat.getAbsoluteGravity(dropDownGravity, ViewCompat.getLayoutDirection(this.mAnchorView));
        }
    }

    @Override // androidx.appcompat.view.menu.MenuPopup
    public void setAnchorView(View anchor) {
        if (this.mAnchorView != anchor) {
            this.mAnchorView = anchor;
            this.mDropDownGravity = GravityCompat.getAbsoluteGravity(this.mRawDropDownGravity, ViewCompat.getLayoutDirection(anchor));
        }
    }

    @Override // androidx.appcompat.view.menu.MenuPopup
    public void setOnDismissListener(PopupWindow.OnDismissListener listener) {
        this.mOnDismissListener = listener;
    }

    @Override // androidx.appcompat.view.menu.ShowableListMenu
    public ListView getListView() {
        if (this.mShowingMenus.isEmpty()) {
            return null;
        }
        List<CascadingMenuInfo> list = this.mShowingMenus;
        return list.get(list.size() - 1).getListView();
    }

    @Override // androidx.appcompat.view.menu.MenuPopup
    public void setHorizontalOffset(int x) {
        this.mHasXOffset = true;
        this.mXOffset = x;
    }

    @Override // androidx.appcompat.view.menu.MenuPopup
    public void setVerticalOffset(int y) {
        this.mHasYOffset = true;
        this.mYOffset = y;
    }

    @Override // androidx.appcompat.view.menu.MenuPopup
    public void setShowTitle(boolean showTitle) {
        this.mShowTitle = showTitle;
    }

    @Override // androidx.appcompat.view.menu.MenuPopup
    protected boolean closeMenuOnSubMenuOpened() {
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class CascadingMenuInfo {
        public final MenuBuilder menu;
        public final int position;
        public final MenuPopupWindow window;

        public CascadingMenuInfo(MenuPopupWindow window, MenuBuilder menu, int position) {
            this.window = window;
            this.menu = menu;
            this.position = position;
        }

        public ListView getListView() {
            return this.window.getListView();
        }
    }
}
