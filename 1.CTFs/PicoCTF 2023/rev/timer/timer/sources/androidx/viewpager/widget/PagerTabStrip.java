package androidx.viewpager.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import androidx.core.content.ContextCompat;
import androidx.core.view.ViewCompat;
/* loaded from: classes.dex */
public class PagerTabStrip extends PagerTitleStrip {
    private static final int FULL_UNDERLINE_HEIGHT = 1;
    private static final int INDICATOR_HEIGHT = 3;
    private static final int MIN_PADDING_BOTTOM = 6;
    private static final int MIN_STRIP_HEIGHT = 32;
    private static final int MIN_TEXT_SPACING = 64;
    private static final int TAB_PADDING = 16;
    private static final int TAB_SPACING = 32;
    private static final String TAG = "PagerTabStrip";
    private boolean mDrawFullUnderline;
    private boolean mDrawFullUnderlineSet;
    private int mFullUnderlineHeight;
    private boolean mIgnoreTap;
    private int mIndicatorColor;
    private int mIndicatorHeight;
    private float mInitialMotionX;
    private float mInitialMotionY;
    private int mMinPaddingBottom;
    private int mMinStripHeight;
    private int mMinTextSpacing;
    private int mTabAlpha;
    private int mTabPadding;
    private final Paint mTabPaint;
    private final Rect mTempRect;
    private int mTouchSlop;

    public PagerTabStrip(Context context) {
        this(context, null);
    }

    public PagerTabStrip(Context context, AttributeSet attrs) {
        super(context, attrs);
        Paint paint = new Paint();
        this.mTabPaint = paint;
        this.mTempRect = new Rect();
        this.mTabAlpha = 255;
        this.mDrawFullUnderline = false;
        this.mDrawFullUnderlineSet = false;
        int i = this.mTextColor;
        this.mIndicatorColor = i;
        paint.setColor(i);
        float density = context.getResources().getDisplayMetrics().density;
        this.mIndicatorHeight = (int) ((3.0f * density) + 0.5f);
        this.mMinPaddingBottom = (int) ((6.0f * density) + 0.5f);
        this.mMinTextSpacing = (int) (64.0f * density);
        this.mTabPadding = (int) ((16.0f * density) + 0.5f);
        this.mFullUnderlineHeight = (int) ((1.0f * density) + 0.5f);
        this.mMinStripHeight = (int) ((32.0f * density) + 0.5f);
        this.mTouchSlop = ViewConfiguration.get(context).getScaledTouchSlop();
        setPadding(getPaddingLeft(), getPaddingTop(), getPaddingRight(), getPaddingBottom());
        setTextSpacing(getTextSpacing());
        setWillNotDraw(false);
        this.mPrevText.setFocusable(true);
        this.mPrevText.setOnClickListener(new View.OnClickListener() { // from class: androidx.viewpager.widget.PagerTabStrip.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                PagerTabStrip.this.mPager.setCurrentItem(PagerTabStrip.this.mPager.getCurrentItem() - 1);
            }
        });
        this.mNextText.setFocusable(true);
        this.mNextText.setOnClickListener(new View.OnClickListener() { // from class: androidx.viewpager.widget.PagerTabStrip.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                PagerTabStrip.this.mPager.setCurrentItem(PagerTabStrip.this.mPager.getCurrentItem() + 1);
            }
        });
        if (getBackground() == null) {
            this.mDrawFullUnderline = true;
        }
    }

    public void setTabIndicatorColor(int color) {
        this.mIndicatorColor = color;
        this.mTabPaint.setColor(color);
        invalidate();
    }

    public void setTabIndicatorColorResource(int resId) {
        setTabIndicatorColor(ContextCompat.getColor(getContext(), resId));
    }

    public int getTabIndicatorColor() {
        return this.mIndicatorColor;
    }

    @Override // android.view.View
    public void setPadding(int left, int top, int right, int bottom) {
        if (bottom < this.mMinPaddingBottom) {
            bottom = this.mMinPaddingBottom;
        }
        super.setPadding(left, top, right, bottom);
    }

    @Override // androidx.viewpager.widget.PagerTitleStrip
    public void setTextSpacing(int textSpacing) {
        if (textSpacing < this.mMinTextSpacing) {
            textSpacing = this.mMinTextSpacing;
        }
        super.setTextSpacing(textSpacing);
    }

    @Override // android.view.View
    public void setBackgroundDrawable(Drawable d) {
        super.setBackgroundDrawable(d);
        if (!this.mDrawFullUnderlineSet) {
            this.mDrawFullUnderline = d == null;
        }
    }

    @Override // android.view.View
    public void setBackgroundColor(int color) {
        super.setBackgroundColor(color);
        if (!this.mDrawFullUnderlineSet) {
            this.mDrawFullUnderline = ((-16777216) & color) == 0;
        }
    }

    @Override // android.view.View
    public void setBackgroundResource(int resId) {
        super.setBackgroundResource(resId);
        if (!this.mDrawFullUnderlineSet) {
            this.mDrawFullUnderline = resId == 0;
        }
    }

    public void setDrawFullUnderline(boolean drawFull) {
        this.mDrawFullUnderline = drawFull;
        this.mDrawFullUnderlineSet = true;
        invalidate();
    }

    public boolean getDrawFullUnderline() {
        return this.mDrawFullUnderline;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // androidx.viewpager.widget.PagerTitleStrip
    public int getMinHeight() {
        return Math.max(super.getMinHeight(), this.mMinStripHeight);
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent ev) {
        int action = ev.getAction();
        if (action != 0 && this.mIgnoreTap) {
            return false;
        }
        float x = ev.getX();
        float y = ev.getY();
        switch (action) {
            case 0:
                this.mInitialMotionX = x;
                this.mInitialMotionY = y;
                this.mIgnoreTap = false;
                break;
            case 1:
                if (x < this.mCurrText.getLeft() - this.mTabPadding) {
                    this.mPager.setCurrentItem(this.mPager.getCurrentItem() - 1);
                    break;
                } else if (x > this.mCurrText.getRight() + this.mTabPadding) {
                    this.mPager.setCurrentItem(this.mPager.getCurrentItem() + 1);
                    break;
                }
                break;
            case 2:
                if (Math.abs(x - this.mInitialMotionX) > this.mTouchSlop || Math.abs(y - this.mInitialMotionY) > this.mTouchSlop) {
                    this.mIgnoreTap = true;
                    break;
                }
                break;
        }
        return true;
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int height = getHeight();
        int left = this.mCurrText.getLeft() - this.mTabPadding;
        int right = this.mCurrText.getRight() + this.mTabPadding;
        int top = height - this.mIndicatorHeight;
        this.mTabPaint.setColor((this.mTabAlpha << 24) | (this.mIndicatorColor & ViewCompat.MEASURED_SIZE_MASK));
        canvas.drawRect(left, top, right, height, this.mTabPaint);
        if (this.mDrawFullUnderline) {
            this.mTabPaint.setColor((-16777216) | (this.mIndicatorColor & ViewCompat.MEASURED_SIZE_MASK));
            canvas.drawRect(getPaddingLeft(), height - this.mFullUnderlineHeight, getWidth() - getPaddingRight(), height, this.mTabPaint);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // androidx.viewpager.widget.PagerTitleStrip
    public void updateTextPositions(int position, float positionOffset, boolean force) {
        Rect r = this.mTempRect;
        int bottom = getHeight();
        int left = this.mCurrText.getLeft() - this.mTabPadding;
        int right = this.mCurrText.getRight() + this.mTabPadding;
        int top = bottom - this.mIndicatorHeight;
        r.set(left, top, right, bottom);
        super.updateTextPositions(position, positionOffset, force);
        this.mTabAlpha = (int) (Math.abs(positionOffset - 0.5f) * 2.0f * 255.0f);
        int left2 = this.mCurrText.getLeft() - this.mTabPadding;
        int right2 = this.mCurrText.getRight() + this.mTabPadding;
        r.union(left2, top, right2, bottom);
        invalidate(r);
    }
}
