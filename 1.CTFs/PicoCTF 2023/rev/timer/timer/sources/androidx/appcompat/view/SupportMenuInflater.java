package androidx.appcompat.view;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.graphics.PorterDuff;
import android.util.AttributeSet;
import android.util.Log;
import android.util.Xml;
import android.view.InflateException;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.SubMenu;
import android.view.View;
import androidx.appcompat.R;
import androidx.appcompat.view.menu.MenuItemImpl;
import androidx.appcompat.view.menu.MenuItemWrapperICS;
import androidx.appcompat.widget.DrawableUtils;
import androidx.appcompat.widget.TintTypedArray;
import androidx.core.internal.view.SupportMenu;
import androidx.core.view.ActionProvider;
import androidx.core.view.MenuItemCompat;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import org.xmlpull.v1.XmlPullParserException;
/* loaded from: classes.dex */
public class SupportMenuInflater extends MenuInflater {
    static final Class<?>[] ACTION_PROVIDER_CONSTRUCTOR_SIGNATURE;
    static final Class<?>[] ACTION_VIEW_CONSTRUCTOR_SIGNATURE;
    static final String LOG_TAG = "SupportMenuInflater";
    static final int NO_ID = 0;
    private static final String XML_GROUP = "group";
    private static final String XML_ITEM = "item";
    private static final String XML_MENU = "menu";
    final Object[] mActionProviderConstructorArguments;
    final Object[] mActionViewConstructorArguments;
    Context mContext;
    private Object mRealOwner;

    static {
        Class<?>[] clsArr = {Context.class};
        ACTION_VIEW_CONSTRUCTOR_SIGNATURE = clsArr;
        ACTION_PROVIDER_CONSTRUCTOR_SIGNATURE = clsArr;
    }

    public SupportMenuInflater(Context context) {
        super(context);
        this.mContext = context;
        Object[] objArr = {context};
        this.mActionViewConstructorArguments = objArr;
        this.mActionProviderConstructorArguments = objArr;
    }

    @Override // android.view.MenuInflater
    public void inflate(int menuRes, Menu menu) {
        if (!(menu instanceof SupportMenu)) {
            super.inflate(menuRes, menu);
            return;
        }
        XmlResourceParser parser = null;
        try {
            try {
                parser = this.mContext.getResources().getLayout(menuRes);
                AttributeSet attrs = Xml.asAttributeSet(parser);
                parseMenu(parser, attrs, menu);
            } catch (IOException e) {
                throw new InflateException("Error inflating menu XML", e);
            } catch (XmlPullParserException e2) {
                throw new InflateException("Error inflating menu XML", e2);
            }
        } finally {
            if (parser != null) {
                parser.close();
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x003d, code lost:
        r4 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x003e, code lost:
        if (r4 != false) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x0044, code lost:
        switch(r1) {
            case 1: goto L56;
            case 2: goto L40;
            case 3: goto L11;
            default: goto L60;
        };
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x0049, code lost:
        r8 = r11.getName();
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x004d, code lost:
        if (r2 == false) goto L18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x0053, code lost:
        if (r8.equals(r3) == false) goto L18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x0055, code lost:
        r2 = false;
        r3 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x005d, code lost:
        if (r8.equals(androidx.appcompat.view.SupportMenuInflater.XML_GROUP) == false) goto L22;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x005f, code lost:
        r0.resetGroup();
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x0067, code lost:
        if (r8.equals(androidx.appcompat.view.SupportMenuInflater.XML_ITEM) == false) goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x006d, code lost:
        if (r0.hasAddedItem() != false) goto L34;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x0071, code lost:
        if (r0.itemActionProvider == null) goto L32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x0079, code lost:
        if (r0.itemActionProvider.hasSubMenu() == false) goto L32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x007b, code lost:
        r0.addSubMenuItem();
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x007f, code lost:
        r0.addItem();
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x0087, code lost:
        if (r8.equals(androidx.appcompat.view.SupportMenuInflater.XML_MENU) == false) goto L39;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0089, code lost:
        r4 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x008b, code lost:
        if (r2 == false) goto L41;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x008e, code lost:
        r8 = r11.getName();
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x0096, code lost:
        if (r8.equals(androidx.appcompat.view.SupportMenuInflater.XML_GROUP) == false) goto L45;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x0098, code lost:
        r0.readGroup(r12);
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x00a0, code lost:
        if (r8.equals(androidx.appcompat.view.SupportMenuInflater.XML_ITEM) == false) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x00a2, code lost:
        r0.readItem(r12);
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x00aa, code lost:
        if (r8.equals(androidx.appcompat.view.SupportMenuInflater.XML_MENU) == false) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x00ac, code lost:
        r6 = r0.addSubMenuItem();
        parseMenu(r11, r12, r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x00b4, code lost:
        r2 = true;
        r3 = r8;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x00be, code lost:
        throw new java.lang.RuntimeException("Unexpected end of document");
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x00bf, code lost:
        r1 = r11.next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x00c5, code lost:
        return;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void parseMenu(org.xmlpull.v1.XmlPullParser r11, android.util.AttributeSet r12, android.view.Menu r13) throws org.xmlpull.v1.XmlPullParserException, java.io.IOException {
        /*
            r10 = this;
            androidx.appcompat.view.SupportMenuInflater$MenuState r0 = new androidx.appcompat.view.SupportMenuInflater$MenuState
            r0.<init>(r13)
            int r1 = r11.getEventType()
            r2 = 0
            r3 = 0
        Lb:
            r4 = 2
            java.lang.String r5 = "menu"
            if (r1 != r4) goto L36
            java.lang.String r4 = r11.getName()
            boolean r6 = r4.equals(r5)
            if (r6 == 0) goto L1f
            int r1 = r11.next()
            goto L3d
        L1f:
            java.lang.RuntimeException r5 = new java.lang.RuntimeException
            java.lang.StringBuilder r6 = new java.lang.StringBuilder
            r6.<init>()
            java.lang.String r7 = "Expecting menu, got "
            r6.append(r7)
            r6.append(r4)
            java.lang.String r6 = r6.toString()
            r5.<init>(r6)
            throw r5
        L36:
            int r1 = r11.next()
            r4 = 1
            if (r1 != r4) goto Lb
        L3d:
            r4 = 0
        L3e:
            if (r4 != 0) goto Lc5
            java.lang.String r6 = "item"
            java.lang.String r7 = "group"
            switch(r1) {
                case 1: goto Lb7;
                case 2: goto L8b;
                case 3: goto L49;
                default: goto L47;
            }
        L47:
            goto Lbf
        L49:
            java.lang.String r8 = r11.getName()
            if (r2 == 0) goto L59
            boolean r9 = r8.equals(r3)
            if (r9 == 0) goto L59
            r2 = 0
            r3 = 0
            goto Lbf
        L59:
            boolean r7 = r8.equals(r7)
            if (r7 == 0) goto L63
            r0.resetGroup()
            goto Lbf
        L63:
            boolean r6 = r8.equals(r6)
            if (r6 == 0) goto L83
            boolean r6 = r0.hasAddedItem()
            if (r6 != 0) goto Lbf
            androidx.core.view.ActionProvider r6 = r0.itemActionProvider
            if (r6 == 0) goto L7f
            androidx.core.view.ActionProvider r6 = r0.itemActionProvider
            boolean r6 = r6.hasSubMenu()
            if (r6 == 0) goto L7f
            r0.addSubMenuItem()
            goto Lbf
        L7f:
            r0.addItem()
            goto Lbf
        L83:
            boolean r6 = r8.equals(r5)
            if (r6 == 0) goto Lbf
            r4 = 1
            goto Lbf
        L8b:
            if (r2 == 0) goto L8e
            goto Lbf
        L8e:
            java.lang.String r8 = r11.getName()
            boolean r7 = r8.equals(r7)
            if (r7 == 0) goto L9c
            r0.readGroup(r12)
            goto Lbf
        L9c:
            boolean r6 = r8.equals(r6)
            if (r6 == 0) goto La6
            r0.readItem(r12)
            goto Lbf
        La6:
            boolean r6 = r8.equals(r5)
            if (r6 == 0) goto Lb4
            android.view.SubMenu r6 = r0.addSubMenuItem()
            r10.parseMenu(r11, r12, r6)
            goto Lbf
        Lb4:
            r2 = 1
            r3 = r8
            goto Lbf
        Lb7:
            java.lang.RuntimeException r5 = new java.lang.RuntimeException
            java.lang.String r6 = "Unexpected end of document"
            r5.<init>(r6)
            throw r5
        Lbf:
            int r1 = r11.next()
            goto L3e
        Lc5:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.view.SupportMenuInflater.parseMenu(org.xmlpull.v1.XmlPullParser, android.util.AttributeSet, android.view.Menu):void");
    }

    Object getRealOwner() {
        if (this.mRealOwner == null) {
            this.mRealOwner = findRealOwner(this.mContext);
        }
        return this.mRealOwner;
    }

    private Object findRealOwner(Object owner) {
        if (owner instanceof Activity) {
            return owner;
        }
        if (owner instanceof ContextWrapper) {
            return findRealOwner(((ContextWrapper) owner).getBaseContext());
        }
        return owner;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class InflatedOnMenuItemClickListener implements MenuItem.OnMenuItemClickListener {
        private static final Class<?>[] PARAM_TYPES = {MenuItem.class};
        private Method mMethod;
        private Object mRealOwner;

        public InflatedOnMenuItemClickListener(Object realOwner, String methodName) {
            this.mRealOwner = realOwner;
            Class<?> c = realOwner.getClass();
            try {
                this.mMethod = c.getMethod(methodName, PARAM_TYPES);
            } catch (Exception e) {
                InflateException ex = new InflateException("Couldn't resolve menu item onClick handler " + methodName + " in class " + c.getName());
                ex.initCause(e);
                throw ex;
            }
        }

        @Override // android.view.MenuItem.OnMenuItemClickListener
        public boolean onMenuItemClick(MenuItem item) {
            try {
                if (this.mMethod.getReturnType() == Boolean.TYPE) {
                    return ((Boolean) this.mMethod.invoke(this.mRealOwner, item)).booleanValue();
                }
                this.mMethod.invoke(this.mRealOwner, item);
                return true;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class MenuState {
        private static final int defaultGroupId = 0;
        private static final int defaultItemCategory = 0;
        private static final int defaultItemCheckable = 0;
        private static final boolean defaultItemChecked = false;
        private static final boolean defaultItemEnabled = true;
        private static final int defaultItemId = 0;
        private static final int defaultItemOrder = 0;
        private static final boolean defaultItemVisible = true;
        private int groupCategory;
        private int groupCheckable;
        private boolean groupEnabled;
        private int groupId;
        private int groupOrder;
        private boolean groupVisible;
        ActionProvider itemActionProvider;
        private String itemActionProviderClassName;
        private String itemActionViewClassName;
        private int itemActionViewLayout;
        private boolean itemAdded;
        private int itemAlphabeticModifiers;
        private char itemAlphabeticShortcut;
        private int itemCategoryOrder;
        private int itemCheckable;
        private boolean itemChecked;
        private CharSequence itemContentDescription;
        private boolean itemEnabled;
        private int itemIconResId;
        private ColorStateList itemIconTintList = null;
        private PorterDuff.Mode itemIconTintMode = null;
        private int itemId;
        private String itemListenerMethodName;
        private int itemNumericModifiers;
        private char itemNumericShortcut;
        private int itemShowAsAction;
        private CharSequence itemTitle;
        private CharSequence itemTitleCondensed;
        private CharSequence itemTooltipText;
        private boolean itemVisible;
        private Menu menu;

        public MenuState(Menu menu) {
            this.menu = menu;
            resetGroup();
        }

        public void resetGroup() {
            this.groupId = 0;
            this.groupCategory = 0;
            this.groupOrder = 0;
            this.groupCheckable = 0;
            this.groupVisible = true;
            this.groupEnabled = true;
        }

        public void readGroup(AttributeSet attrs) {
            TypedArray a = SupportMenuInflater.this.mContext.obtainStyledAttributes(attrs, R.styleable.MenuGroup);
            this.groupId = a.getResourceId(R.styleable.MenuGroup_android_id, 0);
            this.groupCategory = a.getInt(R.styleable.MenuGroup_android_menuCategory, 0);
            this.groupOrder = a.getInt(R.styleable.MenuGroup_android_orderInCategory, 0);
            this.groupCheckable = a.getInt(R.styleable.MenuGroup_android_checkableBehavior, 0);
            this.groupVisible = a.getBoolean(R.styleable.MenuGroup_android_visible, true);
            this.groupEnabled = a.getBoolean(R.styleable.MenuGroup_android_enabled, true);
            a.recycle();
        }

        public void readItem(AttributeSet attrs) {
            TintTypedArray a = TintTypedArray.obtainStyledAttributes(SupportMenuInflater.this.mContext, attrs, R.styleable.MenuItem);
            this.itemId = a.getResourceId(R.styleable.MenuItem_android_id, 0);
            int category = a.getInt(R.styleable.MenuItem_android_menuCategory, this.groupCategory);
            int order = a.getInt(R.styleable.MenuItem_android_orderInCategory, this.groupOrder);
            this.itemCategoryOrder = ((-65536) & category) | (65535 & order);
            this.itemTitle = a.getText(R.styleable.MenuItem_android_title);
            this.itemTitleCondensed = a.getText(R.styleable.MenuItem_android_titleCondensed);
            this.itemIconResId = a.getResourceId(R.styleable.MenuItem_android_icon, 0);
            this.itemAlphabeticShortcut = getShortcut(a.getString(R.styleable.MenuItem_android_alphabeticShortcut));
            this.itemAlphabeticModifiers = a.getInt(R.styleable.MenuItem_alphabeticModifiers, 4096);
            this.itemNumericShortcut = getShortcut(a.getString(R.styleable.MenuItem_android_numericShortcut));
            this.itemNumericModifiers = a.getInt(R.styleable.MenuItem_numericModifiers, 4096);
            if (a.hasValue(R.styleable.MenuItem_android_checkable)) {
                this.itemCheckable = a.getBoolean(R.styleable.MenuItem_android_checkable, false) ? 1 : 0;
            } else {
                this.itemCheckable = this.groupCheckable;
            }
            this.itemChecked = a.getBoolean(R.styleable.MenuItem_android_checked, false);
            this.itemVisible = a.getBoolean(R.styleable.MenuItem_android_visible, this.groupVisible);
            this.itemEnabled = a.getBoolean(R.styleable.MenuItem_android_enabled, this.groupEnabled);
            this.itemShowAsAction = a.getInt(R.styleable.MenuItem_showAsAction, -1);
            this.itemListenerMethodName = a.getString(R.styleable.MenuItem_android_onClick);
            this.itemActionViewLayout = a.getResourceId(R.styleable.MenuItem_actionLayout, 0);
            this.itemActionViewClassName = a.getString(R.styleable.MenuItem_actionViewClass);
            String string = a.getString(R.styleable.MenuItem_actionProviderClass);
            this.itemActionProviderClassName = string;
            boolean hasActionProvider = string != null;
            if (hasActionProvider && this.itemActionViewLayout == 0 && this.itemActionViewClassName == null) {
                this.itemActionProvider = (ActionProvider) newInstance(string, SupportMenuInflater.ACTION_PROVIDER_CONSTRUCTOR_SIGNATURE, SupportMenuInflater.this.mActionProviderConstructorArguments);
            } else {
                if (hasActionProvider) {
                    Log.w(SupportMenuInflater.LOG_TAG, "Ignoring attribute 'actionProviderClass'. Action view already specified.");
                }
                this.itemActionProvider = null;
            }
            this.itemContentDescription = a.getText(R.styleable.MenuItem_contentDescription);
            this.itemTooltipText = a.getText(R.styleable.MenuItem_tooltipText);
            if (a.hasValue(R.styleable.MenuItem_iconTintMode)) {
                this.itemIconTintMode = DrawableUtils.parseTintMode(a.getInt(R.styleable.MenuItem_iconTintMode, -1), this.itemIconTintMode);
            } else {
                this.itemIconTintMode = null;
            }
            if (a.hasValue(R.styleable.MenuItem_iconTint)) {
                this.itemIconTintList = a.getColorStateList(R.styleable.MenuItem_iconTint);
            } else {
                this.itemIconTintList = null;
            }
            a.recycle();
            this.itemAdded = false;
        }

        private char getShortcut(String shortcutString) {
            if (shortcutString == null) {
                return (char) 0;
            }
            return shortcutString.charAt(0);
        }

        private void setItem(MenuItem item) {
            item.setChecked(this.itemChecked).setVisible(this.itemVisible).setEnabled(this.itemEnabled).setCheckable(this.itemCheckable >= 1).setTitleCondensed(this.itemTitleCondensed).setIcon(this.itemIconResId);
            int i = this.itemShowAsAction;
            if (i >= 0) {
                item.setShowAsAction(i);
            }
            if (this.itemListenerMethodName != null) {
                if (SupportMenuInflater.this.mContext.isRestricted()) {
                    throw new IllegalStateException("The android:onClick attribute cannot be used within a restricted context");
                }
                item.setOnMenuItemClickListener(new InflatedOnMenuItemClickListener(SupportMenuInflater.this.getRealOwner(), this.itemListenerMethodName));
            }
            if (this.itemCheckable >= 2) {
                if (item instanceof MenuItemImpl) {
                    ((MenuItemImpl) item).setExclusiveCheckable(true);
                } else if (item instanceof MenuItemWrapperICS) {
                    ((MenuItemWrapperICS) item).setExclusiveCheckable(true);
                }
            }
            boolean actionViewSpecified = false;
            String str = this.itemActionViewClassName;
            if (str != null) {
                View actionView = (View) newInstance(str, SupportMenuInflater.ACTION_VIEW_CONSTRUCTOR_SIGNATURE, SupportMenuInflater.this.mActionViewConstructorArguments);
                item.setActionView(actionView);
                actionViewSpecified = true;
            }
            int i2 = this.itemActionViewLayout;
            if (i2 > 0) {
                if (!actionViewSpecified) {
                    item.setActionView(i2);
                } else {
                    Log.w(SupportMenuInflater.LOG_TAG, "Ignoring attribute 'itemActionViewLayout'. Action view already specified.");
                }
            }
            ActionProvider actionProvider = this.itemActionProvider;
            if (actionProvider != null) {
                MenuItemCompat.setActionProvider(item, actionProvider);
            }
            MenuItemCompat.setContentDescription(item, this.itemContentDescription);
            MenuItemCompat.setTooltipText(item, this.itemTooltipText);
            MenuItemCompat.setAlphabeticShortcut(item, this.itemAlphabeticShortcut, this.itemAlphabeticModifiers);
            MenuItemCompat.setNumericShortcut(item, this.itemNumericShortcut, this.itemNumericModifiers);
            PorterDuff.Mode mode = this.itemIconTintMode;
            if (mode != null) {
                MenuItemCompat.setIconTintMode(item, mode);
            }
            ColorStateList colorStateList = this.itemIconTintList;
            if (colorStateList != null) {
                MenuItemCompat.setIconTintList(item, colorStateList);
            }
        }

        public void addItem() {
            this.itemAdded = true;
            setItem(this.menu.add(this.groupId, this.itemId, this.itemCategoryOrder, this.itemTitle));
        }

        public SubMenu addSubMenuItem() {
            this.itemAdded = true;
            SubMenu subMenu = this.menu.addSubMenu(this.groupId, this.itemId, this.itemCategoryOrder, this.itemTitle);
            setItem(subMenu.getItem());
            return subMenu;
        }

        public boolean hasAddedItem() {
            return this.itemAdded;
        }

        private <T> T newInstance(String className, Class<?>[] constructorSignature, Object[] arguments) {
            try {
                Class<?> clazz = Class.forName(className, false, SupportMenuInflater.this.mContext.getClassLoader());
                Constructor<?> constructor = clazz.getConstructor(constructorSignature);
                constructor.setAccessible(true);
                return (T) constructor.newInstance(arguments);
            } catch (Exception e) {
                Log.w(SupportMenuInflater.LOG_TAG, "Cannot instantiate class: " + className, e);
                return null;
            }
        }
    }
}
