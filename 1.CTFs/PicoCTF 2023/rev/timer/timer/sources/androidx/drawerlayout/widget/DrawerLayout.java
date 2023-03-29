package androidx.drawerlayout.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.SystemClock;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.WindowInsets;
import android.view.accessibility.AccessibilityEvent;
import androidx.constraintlayout.core.widgets.analyzer.BasicMeasure;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.AccessibilityDelegateCompat;
import androidx.core.view.GravityCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.core.view.accessibility.AccessibilityViewCommand;
import androidx.customview.view.AbsSavedState;
import androidx.customview.widget.Openable;
import androidx.customview.widget.ViewDragHelper;
import androidx.drawerlayout.R;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public class DrawerLayout extends ViewGroup implements Openable {
    private static final String ACCESSIBILITY_CLASS_NAME = "androidx.drawerlayout.widget.DrawerLayout";
    private static final boolean ALLOW_EDGE_LOCK = false;
    static final boolean CAN_HIDE_DESCENDANTS;
    private static final boolean CHILDREN_DISALLOW_INTERCEPT = true;
    private static final int DEFAULT_SCRIM_COLOR = -1728053248;
    static final int[] LAYOUT_ATTRS;
    public static final int LOCK_MODE_LOCKED_CLOSED = 1;
    public static final int LOCK_MODE_LOCKED_OPEN = 2;
    public static final int LOCK_MODE_UNDEFINED = 3;
    public static final int LOCK_MODE_UNLOCKED = 0;
    private static final int MIN_DRAWER_MARGIN = 64;
    private static final int MIN_FLING_VELOCITY = 400;
    private static final int PEEK_DELAY = 160;
    private static final boolean SET_DRAWER_SHADOW_FROM_ELEVATION;
    public static final int STATE_DRAGGING = 1;
    public static final int STATE_IDLE = 0;
    public static final int STATE_SETTLING = 2;
    private static final String TAG = "DrawerLayout";
    private static final int[] THEME_ATTRS;
    private static final float TOUCH_SLOP_SENSITIVITY = 1.0f;
    private static boolean sEdgeSizeUsingSystemGestureInsets;
    private final AccessibilityViewCommand mActionDismiss;
    private final ChildAccessibilityDelegate mChildAccessibilityDelegate;
    private Rect mChildHitRect;
    private Matrix mChildInvertedMatrix;
    private boolean mChildrenCanceledTouch;
    private boolean mDrawStatusBarBackground;
    private float mDrawerElevation;
    private int mDrawerState;
    private boolean mFirstLayout;
    private boolean mInLayout;
    private float mInitialMotionX;
    private float mInitialMotionY;
    private Object mLastInsets;
    private final ViewDragCallback mLeftCallback;
    private final ViewDragHelper mLeftDragger;
    private DrawerListener mListener;
    private List<DrawerListener> mListeners;
    private int mLockModeEnd;
    private int mLockModeLeft;
    private int mLockModeRight;
    private int mLockModeStart;
    private int mMinDrawerMargin;
    private final ArrayList<View> mNonDrawerViews;
    private final ViewDragCallback mRightCallback;
    private final ViewDragHelper mRightDragger;
    private int mScrimColor;
    private float mScrimOpacity;
    private Paint mScrimPaint;
    private Drawable mShadowEnd;
    private Drawable mShadowLeft;
    private Drawable mShadowLeftResolved;
    private Drawable mShadowRight;
    private Drawable mShadowRightResolved;
    private Drawable mShadowStart;
    private Drawable mStatusBarBackground;
    private CharSequence mTitleLeft;
    private CharSequence mTitleRight;

    /* loaded from: classes.dex */
    public interface DrawerListener {
        void onDrawerClosed(View view);

        void onDrawerOpened(View view);

        void onDrawerSlide(View view, float f);

        void onDrawerStateChanged(int i);
    }

    static {
        boolean z = CHILDREN_DISALLOW_INTERCEPT;
        THEME_ATTRS = new int[]{16843828};
        LAYOUT_ATTRS = new int[]{16842931};
        CAN_HIDE_DESCENDANTS = Build.VERSION.SDK_INT >= 19 ? CHILDREN_DISALLOW_INTERCEPT : false;
        SET_DRAWER_SHADOW_FROM_ELEVATION = Build.VERSION.SDK_INT >= 21 ? CHILDREN_DISALLOW_INTERCEPT : false;
        if (Build.VERSION.SDK_INT < 29) {
            z = false;
        }
        sEdgeSizeUsingSystemGestureInsets = z;
    }

    /* loaded from: classes.dex */
    public static abstract class SimpleDrawerListener implements DrawerListener {
        @Override // androidx.drawerlayout.widget.DrawerLayout.DrawerListener
        public void onDrawerSlide(View drawerView, float slideOffset) {
        }

        @Override // androidx.drawerlayout.widget.DrawerLayout.DrawerListener
        public void onDrawerOpened(View drawerView) {
        }

        @Override // androidx.drawerlayout.widget.DrawerLayout.DrawerListener
        public void onDrawerClosed(View drawerView) {
        }

        @Override // androidx.drawerlayout.widget.DrawerLayout.DrawerListener
        public void onDrawerStateChanged(int newState) {
        }
    }

    public DrawerLayout(Context context) {
        this(context, null);
    }

    public DrawerLayout(Context context, AttributeSet attrs) {
        this(context, attrs, R.attr.drawerLayoutStyle);
    }

    public DrawerLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        TypedArray a;
        this.mChildAccessibilityDelegate = new ChildAccessibilityDelegate();
        this.mScrimColor = DEFAULT_SCRIM_COLOR;
        this.mScrimPaint = new Paint();
        this.mFirstLayout = CHILDREN_DISALLOW_INTERCEPT;
        this.mLockModeLeft = 3;
        this.mLockModeRight = 3;
        this.mLockModeStart = 3;
        this.mLockModeEnd = 3;
        this.mShadowStart = null;
        this.mShadowEnd = null;
        this.mShadowLeft = null;
        this.mShadowRight = null;
        this.mActionDismiss = new AccessibilityViewCommand() { // from class: androidx.drawerlayout.widget.DrawerLayout.1
            @Override // androidx.core.view.accessibility.AccessibilityViewCommand
            public boolean perform(View view, AccessibilityViewCommand.CommandArguments arguments) {
                if (DrawerLayout.this.isDrawerOpen(view) && DrawerLayout.this.getDrawerLockMode(view) != 2) {
                    DrawerLayout.this.closeDrawer(view);
                    return DrawerLayout.CHILDREN_DISALLOW_INTERCEPT;
                }
                return false;
            }
        };
        setDescendantFocusability(262144);
        float density = getResources().getDisplayMetrics().density;
        this.mMinDrawerMargin = (int) ((64.0f * density) + 0.5f);
        float minVel = 400.0f * density;
        ViewDragCallback viewDragCallback = new ViewDragCallback(3);
        this.mLeftCallback = viewDragCallback;
        ViewDragCallback viewDragCallback2 = new ViewDragCallback(5);
        this.mRightCallback = viewDragCallback2;
        ViewDragHelper create = ViewDragHelper.create(this, 1.0f, viewDragCallback);
        this.mLeftDragger = create;
        create.setEdgeTrackingEnabled(1);
        create.setMinVelocity(minVel);
        viewDragCallback.setDragger(create);
        ViewDragHelper create2 = ViewDragHelper.create(this, 1.0f, viewDragCallback2);
        this.mRightDragger = create2;
        create2.setEdgeTrackingEnabled(2);
        create2.setMinVelocity(minVel);
        viewDragCallback2.setDragger(create2);
        setFocusableInTouchMode(CHILDREN_DISALLOW_INTERCEPT);
        ViewCompat.setImportantForAccessibility(this, 1);
        ViewCompat.setAccessibilityDelegate(this, new AccessibilityDelegate());
        setMotionEventSplittingEnabled(false);
        if (ViewCompat.getFitsSystemWindows(this)) {
            if (Build.VERSION.SDK_INT >= 21) {
                setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() { // from class: androidx.drawerlayout.widget.DrawerLayout.2
                    @Override // android.view.View.OnApplyWindowInsetsListener
                    public WindowInsets onApplyWindowInsets(View view, WindowInsets insets) {
                        DrawerLayout drawerLayout = (DrawerLayout) view;
                        drawerLayout.setChildInsets(insets, insets.getSystemWindowInsetTop() > 0 ? DrawerLayout.CHILDREN_DISALLOW_INTERCEPT : false);
                        return insets.consumeSystemWindowInsets();
                    }
                });
                setSystemUiVisibility(1280);
                a = context.obtainStyledAttributes(THEME_ATTRS);
                try {
                    this.mStatusBarBackground = a.getDrawable(0);
                } finally {
                }
            } else {
                this.mStatusBarBackground = null;
            }
        }
        a = context.obtainStyledAttributes(attrs, R.styleable.DrawerLayout, defStyleAttr, 0);
        try {
            if (a.hasValue(R.styleable.DrawerLayout_elevation)) {
                this.mDrawerElevation = a.getDimension(R.styleable.DrawerLayout_elevation, 0.0f);
            } else {
                this.mDrawerElevation = getResources().getDimension(R.dimen.def_drawer_elevation);
            }
            a.recycle();
            this.mNonDrawerViews = new ArrayList<>();
        } finally {
        }
    }

    public void setDrawerElevation(float elevation) {
        this.mDrawerElevation = elevation;
        for (int i = 0; i < getChildCount(); i++) {
            View child = getChildAt(i);
            if (isDrawerView(child)) {
                ViewCompat.setElevation(child, this.mDrawerElevation);
            }
        }
    }

    public float getDrawerElevation() {
        if (SET_DRAWER_SHADOW_FROM_ELEVATION) {
            return this.mDrawerElevation;
        }
        return 0.0f;
    }

    public void setChildInsets(Object insets, boolean draw) {
        this.mLastInsets = insets;
        this.mDrawStatusBarBackground = draw;
        setWillNotDraw((draw || getBackground() != null) ? false : CHILDREN_DISALLOW_INTERCEPT);
        requestLayout();
    }

    public void setDrawerShadow(Drawable shadowDrawable, int gravity) {
        if (SET_DRAWER_SHADOW_FROM_ELEVATION) {
            return;
        }
        if ((gravity & GravityCompat.START) == 8388611) {
            this.mShadowStart = shadowDrawable;
        } else if ((gravity & GravityCompat.END) == 8388613) {
            this.mShadowEnd = shadowDrawable;
        } else if ((gravity & 3) == 3) {
            this.mShadowLeft = shadowDrawable;
        } else if ((gravity & 5) == 5) {
            this.mShadowRight = shadowDrawable;
        } else {
            return;
        }
        resolveShadowDrawables();
        invalidate();
    }

    public void setDrawerShadow(int resId, int gravity) {
        setDrawerShadow(ContextCompat.getDrawable(getContext(), resId), gravity);
    }

    public void setScrimColor(int color) {
        this.mScrimColor = color;
        invalidate();
    }

    @Deprecated
    public void setDrawerListener(DrawerListener listener) {
        DrawerListener drawerListener = this.mListener;
        if (drawerListener != null) {
            removeDrawerListener(drawerListener);
        }
        if (listener != null) {
            addDrawerListener(listener);
        }
        this.mListener = listener;
    }

    public void addDrawerListener(DrawerListener listener) {
        if (listener == null) {
            return;
        }
        if (this.mListeners == null) {
            this.mListeners = new ArrayList();
        }
        this.mListeners.add(listener);
    }

    public void removeDrawerListener(DrawerListener listener) {
        List<DrawerListener> list;
        if (listener == null || (list = this.mListeners) == null) {
            return;
        }
        list.remove(listener);
    }

    public void setDrawerLockMode(int lockMode) {
        setDrawerLockMode(lockMode, 3);
        setDrawerLockMode(lockMode, 5);
    }

    public void setDrawerLockMode(int lockMode, int edgeGravity) {
        int absGravity = GravityCompat.getAbsoluteGravity(edgeGravity, ViewCompat.getLayoutDirection(this));
        switch (edgeGravity) {
            case 3:
                this.mLockModeLeft = lockMode;
                break;
            case 5:
                this.mLockModeRight = lockMode;
                break;
            case GravityCompat.START /* 8388611 */:
                this.mLockModeStart = lockMode;
                break;
            case GravityCompat.END /* 8388613 */:
                this.mLockModeEnd = lockMode;
                break;
        }
        if (lockMode != 0) {
            ViewDragHelper helper = absGravity == 3 ? this.mLeftDragger : this.mRightDragger;
            helper.cancel();
        }
        switch (lockMode) {
            case 1:
                View toClose = findDrawerWithGravity(absGravity);
                if (toClose != null) {
                    closeDrawer(toClose);
                    return;
                }
                return;
            case 2:
                View toOpen = findDrawerWithGravity(absGravity);
                if (toOpen != null) {
                    openDrawer(toOpen);
                    return;
                }
                return;
            default:
                return;
        }
    }

    public void setDrawerLockMode(int lockMode, View drawerView) {
        if (!isDrawerView(drawerView)) {
            throw new IllegalArgumentException("View " + drawerView + " is not a drawer with appropriate layout_gravity");
        }
        int gravity = ((LayoutParams) drawerView.getLayoutParams()).gravity;
        setDrawerLockMode(lockMode, gravity);
    }

    public int getDrawerLockMode(int edgeGravity) {
        int layoutDirection = ViewCompat.getLayoutDirection(this);
        switch (edgeGravity) {
            case 3:
                int rightLockMode = this.mLockModeLeft;
                if (rightLockMode != 3) {
                    return rightLockMode;
                }
                int leftLockMode = layoutDirection == 0 ? this.mLockModeStart : this.mLockModeEnd;
                if (leftLockMode != 3) {
                    return leftLockMode;
                }
                return 0;
            case 5:
                int startLockMode = this.mLockModeRight;
                if (startLockMode != 3) {
                    return startLockMode;
                }
                int rightLockMode2 = layoutDirection == 0 ? this.mLockModeEnd : this.mLockModeStart;
                if (rightLockMode2 != 3) {
                    return rightLockMode2;
                }
                return 0;
            case GravityCompat.START /* 8388611 */:
                int endLockMode = this.mLockModeStart;
                if (endLockMode != 3) {
                    return endLockMode;
                }
                int startLockMode2 = layoutDirection == 0 ? this.mLockModeLeft : this.mLockModeRight;
                if (startLockMode2 != 3) {
                    return startLockMode2;
                }
                return 0;
            case GravityCompat.END /* 8388613 */:
                int i = this.mLockModeEnd;
                if (i != 3) {
                    return i;
                }
                int endLockMode2 = layoutDirection == 0 ? this.mLockModeRight : this.mLockModeLeft;
                if (endLockMode2 != 3) {
                    return endLockMode2;
                }
                return 0;
            default:
                return 0;
        }
    }

    public int getDrawerLockMode(View drawerView) {
        if (!isDrawerView(drawerView)) {
            throw new IllegalArgumentException("View " + drawerView + " is not a drawer");
        }
        int drawerGravity = ((LayoutParams) drawerView.getLayoutParams()).gravity;
        return getDrawerLockMode(drawerGravity);
    }

    public void setDrawerTitle(int edgeGravity, CharSequence title) {
        int absGravity = GravityCompat.getAbsoluteGravity(edgeGravity, ViewCompat.getLayoutDirection(this));
        if (absGravity == 3) {
            this.mTitleLeft = title;
        } else if (absGravity == 5) {
            this.mTitleRight = title;
        }
    }

    public CharSequence getDrawerTitle(int edgeGravity) {
        int absGravity = GravityCompat.getAbsoluteGravity(edgeGravity, ViewCompat.getLayoutDirection(this));
        if (absGravity == 3) {
            return this.mTitleLeft;
        }
        if (absGravity == 5) {
            return this.mTitleRight;
        }
        return null;
    }

    private boolean isInBoundsOfChild(float x, float y, View child) {
        if (this.mChildHitRect == null) {
            this.mChildHitRect = new Rect();
        }
        child.getHitRect(this.mChildHitRect);
        return this.mChildHitRect.contains((int) x, (int) y);
    }

    private boolean dispatchTransformedGenericPointerEvent(MotionEvent event, View child) {
        Matrix childMatrix = child.getMatrix();
        if (!childMatrix.isIdentity()) {
            MotionEvent transformedEvent = getTransformedMotionEvent(event, child);
            boolean handled = child.dispatchGenericMotionEvent(transformedEvent);
            transformedEvent.recycle();
            return handled;
        }
        float offsetX = getScrollX() - child.getLeft();
        float offsetY = getScrollY() - child.getTop();
        event.offsetLocation(offsetX, offsetY);
        boolean handled2 = child.dispatchGenericMotionEvent(event);
        event.offsetLocation(-offsetX, -offsetY);
        return handled2;
    }

    private MotionEvent getTransformedMotionEvent(MotionEvent event, View child) {
        float offsetX = getScrollX() - child.getLeft();
        float offsetY = getScrollY() - child.getTop();
        MotionEvent transformedEvent = MotionEvent.obtain(event);
        transformedEvent.offsetLocation(offsetX, offsetY);
        Matrix childMatrix = child.getMatrix();
        if (!childMatrix.isIdentity()) {
            if (this.mChildInvertedMatrix == null) {
                this.mChildInvertedMatrix = new Matrix();
            }
            childMatrix.invert(this.mChildInvertedMatrix);
            transformedEvent.transform(this.mChildInvertedMatrix);
        }
        return transformedEvent;
    }

    void updateDrawerState(int activeState, View activeDrawer) {
        int state;
        int leftState = this.mLeftDragger.getViewDragState();
        int rightState = this.mRightDragger.getViewDragState();
        if (leftState == 1 || rightState == 1) {
            state = 1;
        } else if (leftState == 2 || rightState == 2) {
            state = 2;
        } else {
            state = 0;
        }
        if (activeDrawer != null && activeState == 0) {
            LayoutParams lp = (LayoutParams) activeDrawer.getLayoutParams();
            if (lp.onScreen == 0.0f) {
                dispatchOnDrawerClosed(activeDrawer);
            } else if (lp.onScreen == 1.0f) {
                dispatchOnDrawerOpened(activeDrawer);
            }
        }
        if (state != this.mDrawerState) {
            this.mDrawerState = state;
            List<DrawerListener> list = this.mListeners;
            if (list != null) {
                int listenerCount = list.size();
                for (int i = listenerCount - 1; i >= 0; i--) {
                    this.mListeners.get(i).onDrawerStateChanged(state);
                }
            }
        }
    }

    void dispatchOnDrawerClosed(View drawerView) {
        View rootView;
        LayoutParams lp = (LayoutParams) drawerView.getLayoutParams();
        if ((lp.openState & 1) == 1) {
            lp.openState = 0;
            List<DrawerListener> list = this.mListeners;
            if (list != null) {
                int listenerCount = list.size();
                for (int i = listenerCount - 1; i >= 0; i--) {
                    this.mListeners.get(i).onDrawerClosed(drawerView);
                }
            }
            updateChildrenImportantForAccessibility(drawerView, false);
            updateChildAccessibilityAction(drawerView);
            if (hasWindowFocus() && (rootView = getRootView()) != null) {
                rootView.sendAccessibilityEvent(32);
            }
        }
    }

    void dispatchOnDrawerOpened(View drawerView) {
        LayoutParams lp = (LayoutParams) drawerView.getLayoutParams();
        if ((lp.openState & 1) == 0) {
            lp.openState = 1;
            List<DrawerListener> list = this.mListeners;
            if (list != null) {
                int listenerCount = list.size();
                for (int i = listenerCount - 1; i >= 0; i--) {
                    this.mListeners.get(i).onDrawerOpened(drawerView);
                }
            }
            updateChildrenImportantForAccessibility(drawerView, CHILDREN_DISALLOW_INTERCEPT);
            updateChildAccessibilityAction(drawerView);
            if (hasWindowFocus()) {
                sendAccessibilityEvent(32);
            }
        }
    }

    private void updateChildrenImportantForAccessibility(View drawerView, boolean isDrawerOpen) {
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = getChildAt(i);
            if ((!isDrawerOpen && !isDrawerView(child)) || (isDrawerOpen && child == drawerView)) {
                ViewCompat.setImportantForAccessibility(child, 1);
            } else {
                ViewCompat.setImportantForAccessibility(child, 4);
            }
        }
    }

    private void updateChildAccessibilityAction(View child) {
        ViewCompat.removeAccessibilityAction(child, AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_DISMISS.getId());
        if (isDrawerOpen(child) && getDrawerLockMode(child) != 2) {
            ViewCompat.replaceAccessibilityAction(child, AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_DISMISS, null, this.mActionDismiss);
        }
    }

    void dispatchOnDrawerSlide(View drawerView, float slideOffset) {
        List<DrawerListener> list = this.mListeners;
        if (list != null) {
            int listenerCount = list.size();
            for (int i = listenerCount - 1; i >= 0; i--) {
                this.mListeners.get(i).onDrawerSlide(drawerView, slideOffset);
            }
        }
    }

    void setDrawerViewOffset(View drawerView, float slideOffset) {
        LayoutParams lp = (LayoutParams) drawerView.getLayoutParams();
        if (slideOffset == lp.onScreen) {
            return;
        }
        lp.onScreen = slideOffset;
        dispatchOnDrawerSlide(drawerView, slideOffset);
    }

    float getDrawerViewOffset(View drawerView) {
        return ((LayoutParams) drawerView.getLayoutParams()).onScreen;
    }

    int getDrawerViewAbsoluteGravity(View drawerView) {
        int gravity = ((LayoutParams) drawerView.getLayoutParams()).gravity;
        return GravityCompat.getAbsoluteGravity(gravity, ViewCompat.getLayoutDirection(this));
    }

    boolean checkDrawerViewAbsoluteGravity(View drawerView, int checkFor) {
        int absGravity = getDrawerViewAbsoluteGravity(drawerView);
        if ((absGravity & checkFor) == checkFor) {
            return CHILDREN_DISALLOW_INTERCEPT;
        }
        return false;
    }

    View findOpenDrawer() {
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = getChildAt(i);
            LayoutParams childLp = (LayoutParams) child.getLayoutParams();
            if ((childLp.openState & 1) == 1) {
                return child;
            }
        }
        return null;
    }

    void moveDrawerToOffset(View drawerView, float slideOffset) {
        float oldOffset = getDrawerViewOffset(drawerView);
        int width = drawerView.getWidth();
        int oldPos = (int) (width * oldOffset);
        int newPos = (int) (width * slideOffset);
        int dx = newPos - oldPos;
        drawerView.offsetLeftAndRight(checkDrawerViewAbsoluteGravity(drawerView, 3) ? dx : -dx);
        setDrawerViewOffset(drawerView, slideOffset);
    }

    View findDrawerWithGravity(int gravity) {
        int absHorizGravity = GravityCompat.getAbsoluteGravity(gravity, ViewCompat.getLayoutDirection(this)) & 7;
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = getChildAt(i);
            int childAbsGravity = getDrawerViewAbsoluteGravity(child);
            if ((childAbsGravity & 7) == absHorizGravity) {
                return child;
            }
        }
        return null;
    }

    static String gravityToString(int gravity) {
        if ((gravity & 3) == 3) {
            return "LEFT";
        }
        if ((gravity & 5) == 5) {
            return "RIGHT";
        }
        return Integer.toHexString(gravity);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.mFirstLayout = CHILDREN_DISALLOW_INTERCEPT;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.mFirstLayout = CHILDREN_DISALLOW_INTERCEPT;
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int widthMode;
        int heightMode;
        boolean applyInsets;
        DrawerLayout drawerLayout = this;
        int widthMode2 = View.MeasureSpec.getMode(widthMeasureSpec);
        int heightMode2 = View.MeasureSpec.getMode(heightMeasureSpec);
        int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
        int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
        if (widthMode2 != 1073741824 || heightMode2 != 1073741824) {
            if (!isInEditMode()) {
                throw new IllegalArgumentException("DrawerLayout must be measured with MeasureSpec.EXACTLY.");
            }
            if (widthMode2 == 0) {
                widthSize = 300;
            }
            if (heightMode2 == 0) {
                heightSize = 300;
            }
        }
        drawerLayout.setMeasuredDimension(widthSize, heightSize);
        boolean applyInsets2 = (drawerLayout.mLastInsets == null || !ViewCompat.getFitsSystemWindows(this)) ? false : CHILDREN_DISALLOW_INTERCEPT;
        int layoutDirection = ViewCompat.getLayoutDirection(this);
        boolean hasDrawerOnLeftEdge = false;
        boolean hasDrawerOnRightEdge = false;
        int childCount = getChildCount();
        int i = 0;
        while (i < childCount) {
            View child = drawerLayout.getChildAt(i);
            if (child.getVisibility() == 8) {
                widthMode = widthMode2;
                heightMode = heightMode2;
                applyInsets = applyInsets2;
            } else {
                LayoutParams lp = (LayoutParams) child.getLayoutParams();
                if (!applyInsets2) {
                    widthMode = widthMode2;
                    heightMode = heightMode2;
                    applyInsets = applyInsets2;
                } else {
                    int cgrav = GravityCompat.getAbsoluteGravity(lp.gravity, layoutDirection);
                    if (ViewCompat.getFitsSystemWindows(child)) {
                        if (Build.VERSION.SDK_INT < 21) {
                            widthMode = widthMode2;
                            heightMode = heightMode2;
                            applyInsets = applyInsets2;
                        } else {
                            WindowInsets wi = (WindowInsets) drawerLayout.mLastInsets;
                            if (cgrav == 3) {
                                widthMode = widthMode2;
                                heightMode = heightMode2;
                                applyInsets = applyInsets2;
                                wi = wi.replaceSystemWindowInsets(wi.getSystemWindowInsetLeft(), wi.getSystemWindowInsetTop(), 0, wi.getSystemWindowInsetBottom());
                            } else {
                                widthMode = widthMode2;
                                heightMode = heightMode2;
                                applyInsets = applyInsets2;
                                if (cgrav == 5) {
                                    wi = wi.replaceSystemWindowInsets(0, wi.getSystemWindowInsetTop(), wi.getSystemWindowInsetRight(), wi.getSystemWindowInsetBottom());
                                }
                            }
                            child.dispatchApplyWindowInsets(wi);
                        }
                    } else {
                        widthMode = widthMode2;
                        heightMode = heightMode2;
                        applyInsets = applyInsets2;
                        if (Build.VERSION.SDK_INT >= 21) {
                            WindowInsets wi2 = (WindowInsets) drawerLayout.mLastInsets;
                            if (cgrav == 3) {
                                wi2 = wi2.replaceSystemWindowInsets(wi2.getSystemWindowInsetLeft(), wi2.getSystemWindowInsetTop(), 0, wi2.getSystemWindowInsetBottom());
                            } else if (cgrav == 5) {
                                wi2 = wi2.replaceSystemWindowInsets(0, wi2.getSystemWindowInsetTop(), wi2.getSystemWindowInsetRight(), wi2.getSystemWindowInsetBottom());
                            }
                            lp.leftMargin = wi2.getSystemWindowInsetLeft();
                            lp.topMargin = wi2.getSystemWindowInsetTop();
                            lp.rightMargin = wi2.getSystemWindowInsetRight();
                            lp.bottomMargin = wi2.getSystemWindowInsetBottom();
                        }
                    }
                }
                if (drawerLayout.isContentView(child)) {
                    int contentWidthSpec = View.MeasureSpec.makeMeasureSpec((widthSize - lp.leftMargin) - lp.rightMargin, BasicMeasure.EXACTLY);
                    int contentHeightSpec = View.MeasureSpec.makeMeasureSpec((heightSize - lp.topMargin) - lp.bottomMargin, BasicMeasure.EXACTLY);
                    child.measure(contentWidthSpec, contentHeightSpec);
                } else if (!drawerLayout.isDrawerView(child)) {
                    throw new IllegalStateException("Child " + child + " at index " + i + " does not have a valid layout_gravity - must be Gravity.LEFT, Gravity.RIGHT or Gravity.NO_GRAVITY");
                } else {
                    if (SET_DRAWER_SHADOW_FROM_ELEVATION) {
                        float elevation = ViewCompat.getElevation(child);
                        float f = drawerLayout.mDrawerElevation;
                        if (elevation != f) {
                            ViewCompat.setElevation(child, f);
                        }
                    }
                    int childGravity = drawerLayout.getDrawerViewAbsoluteGravity(child) & 7;
                    boolean isLeftEdgeDrawer = childGravity == 3 ? CHILDREN_DISALLOW_INTERCEPT : false;
                    if ((isLeftEdgeDrawer && hasDrawerOnLeftEdge) || (!isLeftEdgeDrawer && hasDrawerOnRightEdge)) {
                        throw new IllegalStateException("Child drawer has absolute gravity " + gravityToString(childGravity) + " but this " + TAG + " already has a drawer view along that edge");
                    }
                    if (isLeftEdgeDrawer) {
                        hasDrawerOnLeftEdge = CHILDREN_DISALLOW_INTERCEPT;
                    } else {
                        hasDrawerOnRightEdge = CHILDREN_DISALLOW_INTERCEPT;
                    }
                    int drawerWidthSpec = getChildMeasureSpec(widthMeasureSpec, drawerLayout.mMinDrawerMargin + lp.leftMargin + lp.rightMargin, lp.width);
                    int drawerHeightSpec = getChildMeasureSpec(heightMeasureSpec, lp.topMargin + lp.bottomMargin, lp.height);
                    child.measure(drawerWidthSpec, drawerHeightSpec);
                    i++;
                    drawerLayout = this;
                    widthMode2 = widthMode;
                    heightMode2 = heightMode;
                    applyInsets2 = applyInsets;
                }
            }
            i++;
            drawerLayout = this;
            widthMode2 = widthMode;
            heightMode2 = heightMode;
            applyInsets2 = applyInsets;
        }
    }

    private void resolveShadowDrawables() {
        if (SET_DRAWER_SHADOW_FROM_ELEVATION) {
            return;
        }
        this.mShadowLeftResolved = resolveLeftShadow();
        this.mShadowRightResolved = resolveRightShadow();
    }

    private Drawable resolveLeftShadow() {
        int layoutDirection = ViewCompat.getLayoutDirection(this);
        if (layoutDirection == 0) {
            Drawable drawable = this.mShadowStart;
            if (drawable != null) {
                mirror(drawable, layoutDirection);
                return this.mShadowStart;
            }
        } else {
            Drawable drawable2 = this.mShadowEnd;
            if (drawable2 != null) {
                mirror(drawable2, layoutDirection);
                return this.mShadowEnd;
            }
        }
        return this.mShadowLeft;
    }

    private Drawable resolveRightShadow() {
        int layoutDirection = ViewCompat.getLayoutDirection(this);
        if (layoutDirection == 0) {
            Drawable drawable = this.mShadowEnd;
            if (drawable != null) {
                mirror(drawable, layoutDirection);
                return this.mShadowEnd;
            }
        } else {
            Drawable drawable2 = this.mShadowStart;
            if (drawable2 != null) {
                mirror(drawable2, layoutDirection);
                return this.mShadowStart;
            }
        }
        return this.mShadowRight;
    }

    private void mirror(Drawable drawable, int layoutDirection) {
        if (drawable != null && DrawableCompat.isAutoMirrored(drawable)) {
            DrawableCompat.setLayoutDirection(drawable, layoutDirection);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int l, int t, int r, int b) {
        WindowInsets rootInsets;
        int childLeft;
        float newOffset;
        this.mInLayout = CHILDREN_DISALLOW_INTERCEPT;
        int width = r - l;
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = getChildAt(i);
            if (child.getVisibility() != 8) {
                LayoutParams lp = (LayoutParams) child.getLayoutParams();
                if (isContentView(child)) {
                    child.layout(lp.leftMargin, lp.topMargin, lp.leftMargin + child.getMeasuredWidth(), lp.topMargin + child.getMeasuredHeight());
                } else {
                    int childWidth = child.getMeasuredWidth();
                    int childHeight = child.getMeasuredHeight();
                    if (checkDrawerViewAbsoluteGravity(child, 3)) {
                        childLeft = (-childWidth) + ((int) (childWidth * lp.onScreen));
                        newOffset = (childWidth + childLeft) / childWidth;
                    } else {
                        childLeft = width - ((int) (childWidth * lp.onScreen));
                        newOffset = (width - childLeft) / childWidth;
                    }
                    boolean changeOffset = newOffset != lp.onScreen ? CHILDREN_DISALLOW_INTERCEPT : false;
                    int vgrav = lp.gravity & 112;
                    switch (vgrav) {
                        case 16:
                            int height = b - t;
                            int childTop = (height - childHeight) / 2;
                            if (childTop < lp.topMargin) {
                                childTop = lp.topMargin;
                            } else if (childTop + childHeight > height - lp.bottomMargin) {
                                childTop = (height - lp.bottomMargin) - childHeight;
                            }
                            child.layout(childLeft, childTop, childLeft + childWidth, childTop + childHeight);
                            break;
                        case 80:
                            int height2 = b - t;
                            child.layout(childLeft, (height2 - lp.bottomMargin) - child.getMeasuredHeight(), childLeft + childWidth, height2 - lp.bottomMargin);
                            break;
                        default:
                            child.layout(childLeft, lp.topMargin, childLeft + childWidth, lp.topMargin + childHeight);
                            break;
                    }
                    if (changeOffset) {
                        setDrawerViewOffset(child, newOffset);
                    }
                    int newVisibility = lp.onScreen > 0.0f ? 0 : 4;
                    if (child.getVisibility() != newVisibility) {
                        child.setVisibility(newVisibility);
                    }
                }
            }
        }
        if (sEdgeSizeUsingSystemGestureInsets && (rootInsets = getRootWindowInsets()) != null) {
            WindowInsetsCompat rootInsetsCompat = WindowInsetsCompat.toWindowInsetsCompat(rootInsets);
            Insets gestureInsets = rootInsetsCompat.getSystemGestureInsets();
            ViewDragHelper viewDragHelper = this.mLeftDragger;
            viewDragHelper.setEdgeSize(Math.max(viewDragHelper.getDefaultEdgeSize(), gestureInsets.left));
            ViewDragHelper viewDragHelper2 = this.mRightDragger;
            viewDragHelper2.setEdgeSize(Math.max(viewDragHelper2.getDefaultEdgeSize(), gestureInsets.right));
        }
        this.mInLayout = false;
        this.mFirstLayout = false;
    }

    @Override // android.view.View, android.view.ViewParent
    public void requestLayout() {
        if (!this.mInLayout) {
            super.requestLayout();
        }
    }

    @Override // android.view.View
    public void computeScroll() {
        int childCount = getChildCount();
        float scrimOpacity = 0.0f;
        for (int i = 0; i < childCount; i++) {
            float onscreen = ((LayoutParams) getChildAt(i).getLayoutParams()).onScreen;
            scrimOpacity = Math.max(scrimOpacity, onscreen);
        }
        this.mScrimOpacity = scrimOpacity;
        boolean leftDraggerSettling = this.mLeftDragger.continueSettling(CHILDREN_DISALLOW_INTERCEPT);
        boolean rightDraggerSettling = this.mRightDragger.continueSettling(CHILDREN_DISALLOW_INTERCEPT);
        if (leftDraggerSettling || rightDraggerSettling) {
            ViewCompat.postInvalidateOnAnimation(this);
        }
    }

    private static boolean hasOpaqueBackground(View v) {
        Drawable bg = v.getBackground();
        if (bg == null || bg.getOpacity() != -1) {
            return false;
        }
        return CHILDREN_DISALLOW_INTERCEPT;
    }

    public void setStatusBarBackground(Drawable bg) {
        this.mStatusBarBackground = bg;
        invalidate();
    }

    public Drawable getStatusBarBackgroundDrawable() {
        return this.mStatusBarBackground;
    }

    public void setStatusBarBackground(int resId) {
        this.mStatusBarBackground = resId != 0 ? ContextCompat.getDrawable(getContext(), resId) : null;
        invalidate();
    }

    public void setStatusBarBackgroundColor(int color) {
        this.mStatusBarBackground = new ColorDrawable(color);
        invalidate();
    }

    @Override // android.view.View
    public void onRtlPropertiesChanged(int layoutDirection) {
        resolveShadowDrawables();
    }

    @Override // android.view.View
    public void onDraw(Canvas c) {
        int inset;
        super.onDraw(c);
        if (this.mDrawStatusBarBackground && this.mStatusBarBackground != null) {
            if (Build.VERSION.SDK_INT >= 21) {
                Object obj = this.mLastInsets;
                inset = obj != null ? ((WindowInsets) obj).getSystemWindowInsetTop() : 0;
            } else {
                inset = 0;
            }
            if (inset > 0) {
                this.mStatusBarBackground.setBounds(0, 0, getWidth(), inset);
                this.mStatusBarBackground.draw(c);
            }
        }
    }

    @Override // android.view.ViewGroup
    protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
        int clipLeft;
        int clipRight;
        int height = getHeight();
        boolean drawingContent = isContentView(child);
        int clipLeft2 = 0;
        int clipRight2 = getWidth();
        int restoreCount = canvas.save();
        if (!drawingContent) {
            clipLeft = 0;
            clipRight = clipRight2;
        } else {
            int childCount = getChildCount();
            for (int i = 0; i < childCount; i++) {
                View v = getChildAt(i);
                if (v != child && v.getVisibility() == 0 && hasOpaqueBackground(v) && isDrawerView(v) && v.getHeight() >= height) {
                    if (checkDrawerViewAbsoluteGravity(v, 3)) {
                        int vright = v.getRight();
                        if (vright > clipLeft2) {
                            clipLeft2 = vright;
                        }
                    } else {
                        int vleft = v.getLeft();
                        if (vleft < clipRight2) {
                            clipRight2 = vleft;
                        }
                    }
                }
            }
            canvas.clipRect(clipLeft2, 0, clipRight2, getHeight());
            clipLeft = clipLeft2;
            clipRight = clipRight2;
        }
        boolean result = super.drawChild(canvas, child, drawingTime);
        canvas.restoreToCount(restoreCount);
        float f = this.mScrimOpacity;
        if (f <= 0.0f || !drawingContent) {
            if (this.mShadowLeftResolved == null || !checkDrawerViewAbsoluteGravity(child, 3)) {
                if (this.mShadowRightResolved != null && checkDrawerViewAbsoluteGravity(child, 5)) {
                    int shadowWidth = this.mShadowRightResolved.getIntrinsicWidth();
                    int childLeft = child.getLeft();
                    int showing = getWidth() - childLeft;
                    int drawerPeekDistance = this.mRightDragger.getEdgeSize();
                    float alpha = Math.max(0.0f, Math.min(showing / drawerPeekDistance, 1.0f));
                    Drawable drawable = this.mShadowRightResolved;
                    int i2 = childLeft - shadowWidth;
                    int shadowWidth2 = child.getTop();
                    int showing2 = child.getBottom();
                    drawable.setBounds(i2, shadowWidth2, childLeft, showing2);
                    this.mShadowRightResolved.setAlpha((int) (255.0f * alpha));
                    this.mShadowRightResolved.draw(canvas);
                }
            } else {
                int shadowWidth3 = this.mShadowLeftResolved.getIntrinsicWidth();
                int childRight = child.getRight();
                int drawerPeekDistance2 = this.mLeftDragger.getEdgeSize();
                float alpha2 = Math.max(0.0f, Math.min(childRight / drawerPeekDistance2, 1.0f));
                Drawable drawable2 = this.mShadowLeftResolved;
                int top = child.getTop();
                int i3 = childRight + shadowWidth3;
                int shadowWidth4 = child.getBottom();
                drawable2.setBounds(childRight, top, i3, shadowWidth4);
                this.mShadowLeftResolved.setAlpha((int) (255.0f * alpha2));
                this.mShadowLeftResolved.draw(canvas);
            }
        } else {
            int i4 = this.mScrimColor;
            int baseAlpha = ((-16777216) & i4) >>> 24;
            int imag = (int) (baseAlpha * f);
            int color = (imag << 24) | (i4 & ViewCompat.MEASURED_SIZE_MASK);
            this.mScrimPaint.setColor(color);
            canvas.drawRect(clipLeft, 0.0f, clipRight, getHeight(), this.mScrimPaint);
        }
        return result;
    }

    boolean isContentView(View child) {
        if (((LayoutParams) child.getLayoutParams()).gravity == 0) {
            return CHILDREN_DISALLOW_INTERCEPT;
        }
        return false;
    }

    boolean isDrawerView(View child) {
        int gravity = ((LayoutParams) child.getLayoutParams()).gravity;
        int absGravity = GravityCompat.getAbsoluteGravity(gravity, ViewCompat.getLayoutDirection(child));
        if ((absGravity & 3) == 0 && (absGravity & 5) == 0) {
            return false;
        }
        return CHILDREN_DISALLOW_INTERCEPT;
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        View child;
        int action = ev.getActionMasked();
        boolean interceptForDrag = this.mLeftDragger.shouldInterceptTouchEvent(ev) | this.mRightDragger.shouldInterceptTouchEvent(ev);
        boolean interceptForTap = false;
        switch (action) {
            case 0:
                float x = ev.getX();
                float y = ev.getY();
                this.mInitialMotionX = x;
                this.mInitialMotionY = y;
                if (this.mScrimOpacity > 0.0f && (child = this.mLeftDragger.findTopChildUnder((int) x, (int) y)) != null && isContentView(child)) {
                    interceptForTap = CHILDREN_DISALLOW_INTERCEPT;
                }
                this.mChildrenCanceledTouch = false;
                break;
            case 1:
            case 3:
                closeDrawers(CHILDREN_DISALLOW_INTERCEPT);
                this.mChildrenCanceledTouch = false;
                break;
            case 2:
                if (this.mLeftDragger.checkTouchSlop(3)) {
                    this.mLeftCallback.removeCallbacks();
                    this.mRightCallback.removeCallbacks();
                    break;
                }
                break;
        }
        if (interceptForDrag || interceptForTap || hasPeekingDrawer() || this.mChildrenCanceledTouch) {
            return CHILDREN_DISALLOW_INTERCEPT;
        }
        return false;
    }

    @Override // android.view.View
    public boolean dispatchGenericMotionEvent(MotionEvent event) {
        if ((event.getSource() & 2) == 0 || event.getAction() == 10 || this.mScrimOpacity <= 0.0f) {
            return super.dispatchGenericMotionEvent(event);
        }
        int childrenCount = getChildCount();
        if (childrenCount != 0) {
            float x = event.getX();
            float y = event.getY();
            for (int i = childrenCount - 1; i >= 0; i--) {
                View child = getChildAt(i);
                if (isInBoundsOfChild(x, y, child) && !isContentView(child) && dispatchTransformedGenericPointerEvent(event, child)) {
                    return CHILDREN_DISALLOW_INTERCEPT;
                }
            }
            return false;
        }
        return false;
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent ev) {
        View openDrawer;
        this.mLeftDragger.processTouchEvent(ev);
        this.mRightDragger.processTouchEvent(ev);
        int action = ev.getAction();
        switch (action & 255) {
            case 0:
                float x = ev.getX();
                float y = ev.getY();
                this.mInitialMotionX = x;
                this.mInitialMotionY = y;
                this.mChildrenCanceledTouch = false;
                break;
            case 1:
                float x2 = ev.getX();
                float y2 = ev.getY();
                boolean peekingOnly = CHILDREN_DISALLOW_INTERCEPT;
                View touchedView = this.mLeftDragger.findTopChildUnder((int) x2, (int) y2);
                if (touchedView != null && isContentView(touchedView)) {
                    float dx = x2 - this.mInitialMotionX;
                    float dy = y2 - this.mInitialMotionY;
                    int slop = this.mLeftDragger.getTouchSlop();
                    if ((dx * dx) + (dy * dy) < slop * slop && (openDrawer = findOpenDrawer()) != null) {
                        peekingOnly = getDrawerLockMode(openDrawer) == 2 ? CHILDREN_DISALLOW_INTERCEPT : false;
                    }
                }
                closeDrawers(peekingOnly);
                break;
            case 3:
                closeDrawers(CHILDREN_DISALLOW_INTERCEPT);
                this.mChildrenCanceledTouch = false;
                break;
        }
        return CHILDREN_DISALLOW_INTERCEPT;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public void requestDisallowInterceptTouchEvent(boolean disallowIntercept) {
        super.requestDisallowInterceptTouchEvent(disallowIntercept);
        if (disallowIntercept) {
            closeDrawers(CHILDREN_DISALLOW_INTERCEPT);
        }
    }

    public void closeDrawers() {
        closeDrawers(false);
    }

    void closeDrawers(boolean peekingOnly) {
        boolean needsInvalidate = false;
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = getChildAt(i);
            LayoutParams lp = (LayoutParams) child.getLayoutParams();
            if (isDrawerView(child) && (!peekingOnly || lp.isPeeking)) {
                int childWidth = child.getWidth();
                if (checkDrawerViewAbsoluteGravity(child, 3)) {
                    needsInvalidate |= this.mLeftDragger.smoothSlideViewTo(child, -childWidth, child.getTop());
                } else {
                    needsInvalidate |= this.mRightDragger.smoothSlideViewTo(child, getWidth(), child.getTop());
                }
                lp.isPeeking = false;
            }
        }
        this.mLeftCallback.removeCallbacks();
        this.mRightCallback.removeCallbacks();
        if (needsInvalidate) {
            invalidate();
        }
    }

    @Override // androidx.customview.widget.Openable
    public void open() {
        openDrawer(GravityCompat.START);
    }

    public void openDrawer(View drawerView) {
        openDrawer(drawerView, CHILDREN_DISALLOW_INTERCEPT);
    }

    public void openDrawer(View drawerView, boolean animate) {
        if (!isDrawerView(drawerView)) {
            throw new IllegalArgumentException("View " + drawerView + " is not a sliding drawer");
        }
        LayoutParams lp = (LayoutParams) drawerView.getLayoutParams();
        if (this.mFirstLayout) {
            lp.onScreen = 1.0f;
            lp.openState = 1;
            updateChildrenImportantForAccessibility(drawerView, CHILDREN_DISALLOW_INTERCEPT);
            updateChildAccessibilityAction(drawerView);
        } else if (animate) {
            lp.openState |= 2;
            if (checkDrawerViewAbsoluteGravity(drawerView, 3)) {
                this.mLeftDragger.smoothSlideViewTo(drawerView, 0, drawerView.getTop());
            } else {
                this.mRightDragger.smoothSlideViewTo(drawerView, getWidth() - drawerView.getWidth(), drawerView.getTop());
            }
        } else {
            moveDrawerToOffset(drawerView, 1.0f);
            updateDrawerState(0, drawerView);
            drawerView.setVisibility(0);
        }
        invalidate();
    }

    public void openDrawer(int gravity) {
        openDrawer(gravity, CHILDREN_DISALLOW_INTERCEPT);
    }

    public void openDrawer(int gravity, boolean animate) {
        View drawerView = findDrawerWithGravity(gravity);
        if (drawerView == null) {
            throw new IllegalArgumentException("No drawer view found with gravity " + gravityToString(gravity));
        }
        openDrawer(drawerView, animate);
    }

    @Override // androidx.customview.widget.Openable
    public void close() {
        closeDrawer(GravityCompat.START);
    }

    public void closeDrawer(View drawerView) {
        closeDrawer(drawerView, CHILDREN_DISALLOW_INTERCEPT);
    }

    public void closeDrawer(View drawerView, boolean animate) {
        if (!isDrawerView(drawerView)) {
            throw new IllegalArgumentException("View " + drawerView + " is not a sliding drawer");
        }
        LayoutParams lp = (LayoutParams) drawerView.getLayoutParams();
        if (this.mFirstLayout) {
            lp.onScreen = 0.0f;
            lp.openState = 0;
        } else if (animate) {
            lp.openState = 4 | lp.openState;
            if (checkDrawerViewAbsoluteGravity(drawerView, 3)) {
                this.mLeftDragger.smoothSlideViewTo(drawerView, -drawerView.getWidth(), drawerView.getTop());
            } else {
                this.mRightDragger.smoothSlideViewTo(drawerView, getWidth(), drawerView.getTop());
            }
        } else {
            moveDrawerToOffset(drawerView, 0.0f);
            updateDrawerState(0, drawerView);
            drawerView.setVisibility(4);
        }
        invalidate();
    }

    public void closeDrawer(int gravity) {
        closeDrawer(gravity, CHILDREN_DISALLOW_INTERCEPT);
    }

    public void closeDrawer(int gravity, boolean animate) {
        View drawerView = findDrawerWithGravity(gravity);
        if (drawerView == null) {
            throw new IllegalArgumentException("No drawer view found with gravity " + gravityToString(gravity));
        }
        closeDrawer(drawerView, animate);
    }

    public boolean isDrawerOpen(View drawer) {
        if (!isDrawerView(drawer)) {
            throw new IllegalArgumentException("View " + drawer + " is not a drawer");
        }
        LayoutParams drawerLp = (LayoutParams) drawer.getLayoutParams();
        if ((drawerLp.openState & 1) == 1) {
            return CHILDREN_DISALLOW_INTERCEPT;
        }
        return false;
    }

    @Override // androidx.customview.widget.Openable
    public boolean isOpen() {
        return isDrawerOpen(GravityCompat.START);
    }

    public boolean isDrawerOpen(int drawerGravity) {
        View drawerView = findDrawerWithGravity(drawerGravity);
        if (drawerView != null) {
            return isDrawerOpen(drawerView);
        }
        return false;
    }

    public boolean isDrawerVisible(View drawer) {
        if (!isDrawerView(drawer)) {
            throw new IllegalArgumentException("View " + drawer + " is not a drawer");
        } else if (((LayoutParams) drawer.getLayoutParams()).onScreen > 0.0f) {
            return CHILDREN_DISALLOW_INTERCEPT;
        } else {
            return false;
        }
    }

    public boolean isDrawerVisible(int drawerGravity) {
        View drawerView = findDrawerWithGravity(drawerGravity);
        if (drawerView != null) {
            return isDrawerVisible(drawerView);
        }
        return false;
    }

    private boolean hasPeekingDrawer() {
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            LayoutParams lp = (LayoutParams) getChildAt(i).getLayoutParams();
            if (lp.isPeeking) {
                return CHILDREN_DISALLOW_INTERCEPT;
            }
        }
        return false;
    }

    @Override // android.view.ViewGroup
    protected ViewGroup.LayoutParams generateDefaultLayoutParams() {
        return new LayoutParams(-1, -1);
    }

    @Override // android.view.ViewGroup
    protected ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams p) {
        if (p instanceof LayoutParams) {
            return new LayoutParams((LayoutParams) p);
        }
        if (p instanceof ViewGroup.MarginLayoutParams) {
            return new LayoutParams((ViewGroup.MarginLayoutParams) p);
        }
        return new LayoutParams(p);
    }

    @Override // android.view.ViewGroup
    protected boolean checkLayoutParams(ViewGroup.LayoutParams p) {
        if ((p instanceof LayoutParams) && super.checkLayoutParams(p)) {
            return CHILDREN_DISALLOW_INTERCEPT;
        }
        return false;
    }

    @Override // android.view.ViewGroup
    public ViewGroup.LayoutParams generateLayoutParams(AttributeSet attrs) {
        return new LayoutParams(getContext(), attrs);
    }

    @Override // android.view.ViewGroup, android.view.View
    public void addFocusables(ArrayList<View> views, int direction, int focusableMode) {
        if (getDescendantFocusability() == 393216) {
            return;
        }
        int childCount = getChildCount();
        boolean isDrawerOpen = false;
        for (int i = 0; i < childCount; i++) {
            View child = getChildAt(i);
            if (isDrawerView(child)) {
                if (isDrawerOpen(child)) {
                    isDrawerOpen = CHILDREN_DISALLOW_INTERCEPT;
                    child.addFocusables(views, direction, focusableMode);
                }
            } else {
                this.mNonDrawerViews.add(child);
            }
        }
        if (!isDrawerOpen) {
            int nonDrawerViewsCount = this.mNonDrawerViews.size();
            for (int i2 = 0; i2 < nonDrawerViewsCount; i2++) {
                View child2 = this.mNonDrawerViews.get(i2);
                if (child2.getVisibility() == 0) {
                    child2.addFocusables(views, direction, focusableMode);
                }
            }
        }
        this.mNonDrawerViews.clear();
    }

    private boolean hasVisibleDrawer() {
        if (findVisibleDrawer() != null) {
            return CHILDREN_DISALLOW_INTERCEPT;
        }
        return false;
    }

    View findVisibleDrawer() {
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = getChildAt(i);
            if (isDrawerView(child) && isDrawerVisible(child)) {
                return child;
            }
        }
        return null;
    }

    void cancelChildViewTouch() {
        if (!this.mChildrenCanceledTouch) {
            long now = SystemClock.uptimeMillis();
            MotionEvent cancelEvent = MotionEvent.obtain(now, now, 3, 0.0f, 0.0f, 0);
            int childCount = getChildCount();
            for (int i = 0; i < childCount; i++) {
                getChildAt(i).dispatchTouchEvent(cancelEvent);
            }
            cancelEvent.recycle();
            this.mChildrenCanceledTouch = CHILDREN_DISALLOW_INTERCEPT;
        }
    }

    @Override // android.view.View, android.view.KeyEvent.Callback
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == 4 && hasVisibleDrawer()) {
            event.startTracking();
            return CHILDREN_DISALLOW_INTERCEPT;
        }
        return super.onKeyDown(keyCode, event);
    }

    @Override // android.view.View, android.view.KeyEvent.Callback
    public boolean onKeyUp(int keyCode, KeyEvent event) {
        if (keyCode == 4) {
            View visibleDrawer = findVisibleDrawer();
            if (visibleDrawer != null && getDrawerLockMode(visibleDrawer) == 0) {
                closeDrawers();
            }
            if (visibleDrawer != null) {
                return CHILDREN_DISALLOW_INTERCEPT;
            }
            return false;
        }
        return super.onKeyUp(keyCode, event);
    }

    @Override // android.view.View
    protected void onRestoreInstanceState(Parcelable state) {
        View toOpen;
        if (!(state instanceof SavedState)) {
            super.onRestoreInstanceState(state);
            return;
        }
        SavedState ss = (SavedState) state;
        super.onRestoreInstanceState(ss.getSuperState());
        if (ss.openDrawerGravity != 0 && (toOpen = findDrawerWithGravity(ss.openDrawerGravity)) != null) {
            openDrawer(toOpen);
        }
        if (ss.lockModeLeft != 3) {
            setDrawerLockMode(ss.lockModeLeft, 3);
        }
        if (ss.lockModeRight != 3) {
            setDrawerLockMode(ss.lockModeRight, 5);
        }
        if (ss.lockModeStart != 3) {
            setDrawerLockMode(ss.lockModeStart, GravityCompat.START);
        }
        if (ss.lockModeEnd != 3) {
            setDrawerLockMode(ss.lockModeEnd, GravityCompat.END);
        }
    }

    @Override // android.view.View
    protected Parcelable onSaveInstanceState() {
        Parcelable superState = super.onSaveInstanceState();
        SavedState ss = new SavedState(superState);
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = getChildAt(i);
            LayoutParams lp = (LayoutParams) child.getLayoutParams();
            boolean isOpenedAndNotClosing = lp.openState == 1 ? CHILDREN_DISALLOW_INTERCEPT : false;
            boolean isClosedAndOpening = lp.openState == 2 ? CHILDREN_DISALLOW_INTERCEPT : false;
            if (isOpenedAndNotClosing || isClosedAndOpening) {
                ss.openDrawerGravity = lp.gravity;
                break;
            }
        }
        int i2 = this.mLockModeLeft;
        ss.lockModeLeft = i2;
        ss.lockModeRight = this.mLockModeRight;
        ss.lockModeStart = this.mLockModeStart;
        ss.lockModeEnd = this.mLockModeEnd;
        return ss;
    }

    @Override // android.view.ViewGroup
    public void addView(View child, int index, ViewGroup.LayoutParams params) {
        super.addView(child, index, params);
        View openDrawer = findOpenDrawer();
        if (openDrawer != null || isDrawerView(child)) {
            ViewCompat.setImportantForAccessibility(child, 4);
        } else {
            ViewCompat.setImportantForAccessibility(child, 1);
        }
        if (!CAN_HIDE_DESCENDANTS) {
            ViewCompat.setAccessibilityDelegate(child, this.mChildAccessibilityDelegate);
        }
    }

    static boolean includeChildForAccessibility(View child) {
        if (ViewCompat.getImportantForAccessibility(child) == 4 || ViewCompat.getImportantForAccessibility(child) == 2) {
            return false;
        }
        return CHILDREN_DISALLOW_INTERCEPT;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: classes.dex */
    public static class SavedState extends AbsSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new Parcelable.ClassLoaderCreator<SavedState>() { // from class: androidx.drawerlayout.widget.DrawerLayout.SavedState.1
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.ClassLoaderCreator
            public SavedState createFromParcel(Parcel in, ClassLoader loader) {
                return new SavedState(in, loader);
            }

            @Override // android.os.Parcelable.Creator
            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in, null);
            }

            @Override // android.os.Parcelable.Creator
            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        int lockModeEnd;
        int lockModeLeft;
        int lockModeRight;
        int lockModeStart;
        int openDrawerGravity;

        public SavedState(Parcel in, ClassLoader loader) {
            super(in, loader);
            this.openDrawerGravity = 0;
            this.openDrawerGravity = in.readInt();
            this.lockModeLeft = in.readInt();
            this.lockModeRight = in.readInt();
            this.lockModeStart = in.readInt();
            this.lockModeEnd = in.readInt();
        }

        public SavedState(Parcelable superState) {
            super(superState);
            this.openDrawerGravity = 0;
        }

        @Override // androidx.customview.view.AbsSavedState, android.os.Parcelable
        public void writeToParcel(Parcel dest, int flags) {
            super.writeToParcel(dest, flags);
            dest.writeInt(this.openDrawerGravity);
            dest.writeInt(this.lockModeLeft);
            dest.writeInt(this.lockModeRight);
            dest.writeInt(this.lockModeStart);
            dest.writeInt(this.lockModeEnd);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class ViewDragCallback extends ViewDragHelper.Callback {
        private final int mAbsGravity;
        private ViewDragHelper mDragger;
        private final Runnable mPeekRunnable = new Runnable() { // from class: androidx.drawerlayout.widget.DrawerLayout.ViewDragCallback.1
            @Override // java.lang.Runnable
            public void run() {
                ViewDragCallback.this.peekDrawer();
            }
        };

        ViewDragCallback(int gravity) {
            this.mAbsGravity = gravity;
        }

        public void setDragger(ViewDragHelper dragger) {
            this.mDragger = dragger;
        }

        public void removeCallbacks() {
            DrawerLayout.this.removeCallbacks(this.mPeekRunnable);
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public boolean tryCaptureView(View child, int pointerId) {
            if (DrawerLayout.this.isDrawerView(child) && DrawerLayout.this.checkDrawerViewAbsoluteGravity(child, this.mAbsGravity) && DrawerLayout.this.getDrawerLockMode(child) == 0) {
                return DrawerLayout.CHILDREN_DISALLOW_INTERCEPT;
            }
            return false;
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public void onViewDragStateChanged(int state) {
            DrawerLayout.this.updateDrawerState(state, this.mDragger.getCapturedView());
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public void onViewPositionChanged(View changedView, int left, int top, int dx, int dy) {
            float offset;
            int childWidth = changedView.getWidth();
            if (DrawerLayout.this.checkDrawerViewAbsoluteGravity(changedView, 3)) {
                offset = (childWidth + left) / childWidth;
            } else {
                int width = DrawerLayout.this.getWidth();
                offset = (width - left) / childWidth;
            }
            DrawerLayout.this.setDrawerViewOffset(changedView, offset);
            changedView.setVisibility(offset == 0.0f ? 4 : 0);
            DrawerLayout.this.invalidate();
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public void onViewCaptured(View capturedChild, int activePointerId) {
            LayoutParams lp = (LayoutParams) capturedChild.getLayoutParams();
            lp.isPeeking = false;
            closeOtherDrawer();
        }

        private void closeOtherDrawer() {
            int otherGrav = this.mAbsGravity == 3 ? 5 : 3;
            View toClose = DrawerLayout.this.findDrawerWithGravity(otherGrav);
            if (toClose != null) {
                DrawerLayout.this.closeDrawer(toClose);
            }
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public void onViewReleased(View releasedChild, float xvel, float yvel) {
            int width;
            float offset = DrawerLayout.this.getDrawerViewOffset(releasedChild);
            int childWidth = releasedChild.getWidth();
            if (DrawerLayout.this.checkDrawerViewAbsoluteGravity(releasedChild, 3)) {
                width = (xvel > 0.0f || (xvel == 0.0f && offset > 0.5f)) ? 0 : -childWidth;
            } else {
                int width2 = DrawerLayout.this.getWidth();
                width = (xvel < 0.0f || (xvel == 0.0f && offset > 0.5f)) ? width2 - childWidth : width2;
            }
            this.mDragger.settleCapturedViewAt(width, releasedChild.getTop());
            DrawerLayout.this.invalidate();
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public void onEdgeTouched(int edgeFlags, int pointerId) {
            DrawerLayout.this.postDelayed(this.mPeekRunnable, 160L);
        }

        void peekDrawer() {
            View toCapture;
            int childLeft;
            int peekDistance = this.mDragger.getEdgeSize();
            boolean leftEdge = this.mAbsGravity == 3 ? DrawerLayout.CHILDREN_DISALLOW_INTERCEPT : false;
            if (leftEdge) {
                toCapture = DrawerLayout.this.findDrawerWithGravity(3);
                childLeft = (toCapture != null ? -toCapture.getWidth() : 0) + peekDistance;
            } else {
                toCapture = DrawerLayout.this.findDrawerWithGravity(5);
                childLeft = DrawerLayout.this.getWidth() - peekDistance;
            }
            if (toCapture != null) {
                if (((leftEdge && toCapture.getLeft() < childLeft) || (!leftEdge && toCapture.getLeft() > childLeft)) && DrawerLayout.this.getDrawerLockMode(toCapture) == 0) {
                    LayoutParams lp = (LayoutParams) toCapture.getLayoutParams();
                    this.mDragger.smoothSlideViewTo(toCapture, childLeft, toCapture.getTop());
                    lp.isPeeking = DrawerLayout.CHILDREN_DISALLOW_INTERCEPT;
                    DrawerLayout.this.invalidate();
                    closeOtherDrawer();
                    DrawerLayout.this.cancelChildViewTouch();
                }
            }
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public boolean onEdgeLock(int edgeFlags) {
            return false;
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public void onEdgeDragStarted(int edgeFlags, int pointerId) {
            View toCapture;
            if ((edgeFlags & 1) == 1) {
                toCapture = DrawerLayout.this.findDrawerWithGravity(3);
            } else {
                toCapture = DrawerLayout.this.findDrawerWithGravity(5);
            }
            if (toCapture != null && DrawerLayout.this.getDrawerLockMode(toCapture) == 0) {
                this.mDragger.captureChildView(toCapture, pointerId);
            }
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public int getViewHorizontalDragRange(View child) {
            if (DrawerLayout.this.isDrawerView(child)) {
                return child.getWidth();
            }
            return 0;
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public int clampViewPositionHorizontal(View child, int left, int dx) {
            if (DrawerLayout.this.checkDrawerViewAbsoluteGravity(child, 3)) {
                return Math.max(-child.getWidth(), Math.min(left, 0));
            }
            int width = DrawerLayout.this.getWidth();
            return Math.max(width - child.getWidth(), Math.min(left, width));
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public int clampViewPositionVertical(View child, int top, int dy) {
            return child.getTop();
        }
    }

    /* loaded from: classes.dex */
    public static class LayoutParams extends ViewGroup.MarginLayoutParams {
        private static final int FLAG_IS_CLOSING = 4;
        private static final int FLAG_IS_OPENED = 1;
        private static final int FLAG_IS_OPENING = 2;
        public int gravity;
        boolean isPeeking;
        float onScreen;
        int openState;

        public LayoutParams(Context c, AttributeSet attrs) {
            super(c, attrs);
            this.gravity = 0;
            TypedArray a = c.obtainStyledAttributes(attrs, DrawerLayout.LAYOUT_ATTRS);
            this.gravity = a.getInt(0, 0);
            a.recycle();
        }

        public LayoutParams(int width, int height) {
            super(width, height);
            this.gravity = 0;
        }

        public LayoutParams(int width, int height, int gravity) {
            this(width, height);
            this.gravity = gravity;
        }

        public LayoutParams(LayoutParams source) {
            super((ViewGroup.MarginLayoutParams) source);
            this.gravity = 0;
            this.gravity = source.gravity;
        }

        public LayoutParams(ViewGroup.LayoutParams source) {
            super(source);
            this.gravity = 0;
        }

        public LayoutParams(ViewGroup.MarginLayoutParams source) {
            super(source);
            this.gravity = 0;
        }
    }

    /* loaded from: classes.dex */
    class AccessibilityDelegate extends AccessibilityDelegateCompat {
        private final Rect mTmpRect = new Rect();

        AccessibilityDelegate() {
        }

        @Override // androidx.core.view.AccessibilityDelegateCompat
        public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
            if (DrawerLayout.CAN_HIDE_DESCENDANTS) {
                super.onInitializeAccessibilityNodeInfo(host, info);
            } else {
                AccessibilityNodeInfoCompat superNode = AccessibilityNodeInfoCompat.obtain(info);
                super.onInitializeAccessibilityNodeInfo(host, superNode);
                info.setSource(host);
                ViewParent parent = ViewCompat.getParentForAccessibility(host);
                if (parent instanceof View) {
                    info.setParent((View) parent);
                }
                copyNodeInfoNoChildren(info, superNode);
                superNode.recycle();
                addChildrenForAccessibility(info, (ViewGroup) host);
            }
            info.setClassName(DrawerLayout.ACCESSIBILITY_CLASS_NAME);
            info.setFocusable(false);
            info.setFocused(false);
            info.removeAction(AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_FOCUS);
            info.removeAction(AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_CLEAR_FOCUS);
        }

        @Override // androidx.core.view.AccessibilityDelegateCompat
        public void onInitializeAccessibilityEvent(View host, AccessibilityEvent event) {
            super.onInitializeAccessibilityEvent(host, event);
            event.setClassName(DrawerLayout.ACCESSIBILITY_CLASS_NAME);
        }

        @Override // androidx.core.view.AccessibilityDelegateCompat
        public boolean dispatchPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
            if (event.getEventType() == 32) {
                List<CharSequence> eventText = event.getText();
                View visibleDrawer = DrawerLayout.this.findVisibleDrawer();
                if (visibleDrawer != null) {
                    int edgeGravity = DrawerLayout.this.getDrawerViewAbsoluteGravity(visibleDrawer);
                    CharSequence title = DrawerLayout.this.getDrawerTitle(edgeGravity);
                    if (title != null) {
                        eventText.add(title);
                        return DrawerLayout.CHILDREN_DISALLOW_INTERCEPT;
                    }
                    return DrawerLayout.CHILDREN_DISALLOW_INTERCEPT;
                }
                return DrawerLayout.CHILDREN_DISALLOW_INTERCEPT;
            }
            return super.dispatchPopulateAccessibilityEvent(host, event);
        }

        @Override // androidx.core.view.AccessibilityDelegateCompat
        public boolean onRequestSendAccessibilityEvent(ViewGroup host, View child, AccessibilityEvent event) {
            if (DrawerLayout.CAN_HIDE_DESCENDANTS || DrawerLayout.includeChildForAccessibility(child)) {
                return super.onRequestSendAccessibilityEvent(host, child, event);
            }
            return false;
        }

        private void addChildrenForAccessibility(AccessibilityNodeInfoCompat info, ViewGroup v) {
            int childCount = v.getChildCount();
            for (int i = 0; i < childCount; i++) {
                View child = v.getChildAt(i);
                if (DrawerLayout.includeChildForAccessibility(child)) {
                    info.addChild(child);
                }
            }
        }

        private void copyNodeInfoNoChildren(AccessibilityNodeInfoCompat dest, AccessibilityNodeInfoCompat src) {
            Rect rect = this.mTmpRect;
            src.getBoundsInScreen(rect);
            dest.setBoundsInScreen(rect);
            dest.setVisibleToUser(src.isVisibleToUser());
            dest.setPackageName(src.getPackageName());
            dest.setClassName(src.getClassName());
            dest.setContentDescription(src.getContentDescription());
            dest.setEnabled(src.isEnabled());
            dest.setFocused(src.isFocused());
            dest.setAccessibilityFocused(src.isAccessibilityFocused());
            dest.setSelected(src.isSelected());
            dest.addAction(src.getActions());
        }
    }

    /* loaded from: classes.dex */
    static final class ChildAccessibilityDelegate extends AccessibilityDelegateCompat {
        ChildAccessibilityDelegate() {
        }

        @Override // androidx.core.view.AccessibilityDelegateCompat
        public void onInitializeAccessibilityNodeInfo(View child, AccessibilityNodeInfoCompat info) {
            super.onInitializeAccessibilityNodeInfo(child, info);
            if (!DrawerLayout.includeChildForAccessibility(child)) {
                info.setParent(null);
            }
        }
    }
}
