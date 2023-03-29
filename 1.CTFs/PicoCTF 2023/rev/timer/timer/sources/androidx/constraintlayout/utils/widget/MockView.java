package androidx.constraintlayout.utils.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.view.View;
import androidx.constraintlayout.widget.R;
import androidx.recyclerview.widget.ItemTouchHelper;
/* loaded from: classes.dex */
public class MockView extends View {
    private int mDiagonalsColor;
    private boolean mDrawDiagonals;
    private boolean mDrawLabel;
    private int mMargin;
    private Paint mPaintDiagonals;
    private Paint mPaintText;
    private Paint mPaintTextBackground;
    protected String mText;
    private int mTextBackgroundColor;
    private Rect mTextBounds;
    private int mTextColor;

    public MockView(Context context) {
        super(context);
        this.mPaintDiagonals = new Paint();
        this.mPaintText = new Paint();
        this.mPaintTextBackground = new Paint();
        this.mDrawDiagonals = true;
        this.mDrawLabel = true;
        this.mText = null;
        this.mTextBounds = new Rect();
        this.mDiagonalsColor = Color.argb(255, 0, 0, 0);
        this.mTextColor = Color.argb(255, (int) ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, (int) ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, (int) ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION);
        this.mTextBackgroundColor = Color.argb(255, 50, 50, 50);
        this.mMargin = 4;
        init(context, null);
    }

    public MockView(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mPaintDiagonals = new Paint();
        this.mPaintText = new Paint();
        this.mPaintTextBackground = new Paint();
        this.mDrawDiagonals = true;
        this.mDrawLabel = true;
        this.mText = null;
        this.mTextBounds = new Rect();
        this.mDiagonalsColor = Color.argb(255, 0, 0, 0);
        this.mTextColor = Color.argb(255, (int) ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, (int) ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, (int) ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION);
        this.mTextBackgroundColor = Color.argb(255, 50, 50, 50);
        this.mMargin = 4;
        init(context, attrs);
    }

    public MockView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mPaintDiagonals = new Paint();
        this.mPaintText = new Paint();
        this.mPaintTextBackground = new Paint();
        this.mDrawDiagonals = true;
        this.mDrawLabel = true;
        this.mText = null;
        this.mTextBounds = new Rect();
        this.mDiagonalsColor = Color.argb(255, 0, 0, 0);
        this.mTextColor = Color.argb(255, (int) ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, (int) ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, (int) ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION);
        this.mTextBackgroundColor = Color.argb(255, 50, 50, 50);
        this.mMargin = 4;
        init(context, attrs);
    }

    private void init(Context context, AttributeSet attrs) {
        if (attrs != null) {
            TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.MockView);
            int N = a.getIndexCount();
            for (int i = 0; i < N; i++) {
                int attr = a.getIndex(i);
                if (attr == R.styleable.MockView_mock_label) {
                    this.mText = a.getString(attr);
                } else if (attr == R.styleable.MockView_mock_showDiagonals) {
                    this.mDrawDiagonals = a.getBoolean(attr, this.mDrawDiagonals);
                } else if (attr == R.styleable.MockView_mock_diagonalsColor) {
                    this.mDiagonalsColor = a.getColor(attr, this.mDiagonalsColor);
                } else if (attr == R.styleable.MockView_mock_labelBackgroundColor) {
                    this.mTextBackgroundColor = a.getColor(attr, this.mTextBackgroundColor);
                } else if (attr == R.styleable.MockView_mock_labelColor) {
                    this.mTextColor = a.getColor(attr, this.mTextColor);
                } else if (attr == R.styleable.MockView_mock_showLabel) {
                    this.mDrawLabel = a.getBoolean(attr, this.mDrawLabel);
                }
            }
            a.recycle();
        }
        if (this.mText == null) {
            try {
                this.mText = context.getResources().getResourceEntryName(getId());
            } catch (Exception e) {
            }
        }
        this.mPaintDiagonals.setColor(this.mDiagonalsColor);
        this.mPaintDiagonals.setAntiAlias(true);
        this.mPaintText.setColor(this.mTextColor);
        this.mPaintText.setAntiAlias(true);
        this.mPaintTextBackground.setColor(this.mTextBackgroundColor);
        this.mMargin = Math.round(this.mMargin * (getResources().getDisplayMetrics().xdpi / 160.0f));
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int w = getWidth();
        int h = getHeight();
        if (this.mDrawDiagonals) {
            w--;
            h--;
            canvas.drawLine(0.0f, 0.0f, w, h, this.mPaintDiagonals);
            canvas.drawLine(0.0f, h, w, 0.0f, this.mPaintDiagonals);
            canvas.drawLine(0.0f, 0.0f, w, 0.0f, this.mPaintDiagonals);
            canvas.drawLine(w, 0.0f, w, h, this.mPaintDiagonals);
            canvas.drawLine(w, h, 0.0f, h, this.mPaintDiagonals);
            canvas.drawLine(0.0f, h, 0.0f, 0.0f, this.mPaintDiagonals);
        }
        String str = this.mText;
        if (str != null && this.mDrawLabel) {
            this.mPaintText.getTextBounds(str, 0, str.length(), this.mTextBounds);
            float tx = (w - this.mTextBounds.width()) / 2.0f;
            float ty = ((h - this.mTextBounds.height()) / 2.0f) + this.mTextBounds.height();
            this.mTextBounds.offset((int) tx, (int) ty);
            Rect rect = this.mTextBounds;
            rect.set(rect.left - this.mMargin, this.mTextBounds.top - this.mMargin, this.mTextBounds.right + this.mMargin, this.mTextBounds.bottom + this.mMargin);
            canvas.drawRect(this.mTextBounds, this.mPaintTextBackground);
            canvas.drawText(this.mText, tx, ty, this.mPaintText);
        }
    }
}
