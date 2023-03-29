package androidx.core.view;

import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.Message;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.ViewConfiguration;
/* loaded from: classes.dex */
public final class GestureDetectorCompat {
    private final GestureDetectorCompatImpl mImpl;

    /* loaded from: classes.dex */
    interface GestureDetectorCompatImpl {
        boolean isLongpressEnabled();

        boolean onTouchEvent(MotionEvent motionEvent);

        void setIsLongpressEnabled(boolean z);

        void setOnDoubleTapListener(GestureDetector.OnDoubleTapListener onDoubleTapListener);
    }

    /* loaded from: classes.dex */
    static class GestureDetectorCompatImplBase implements GestureDetectorCompatImpl {
        private static final int LONG_PRESS = 2;
        private static final int SHOW_PRESS = 1;
        private static final int TAP = 3;
        private boolean mAlwaysInBiggerTapRegion;
        private boolean mAlwaysInTapRegion;
        MotionEvent mCurrentDownEvent;
        boolean mDeferConfirmSingleTap;
        GestureDetector.OnDoubleTapListener mDoubleTapListener;
        private int mDoubleTapSlopSquare;
        private float mDownFocusX;
        private float mDownFocusY;
        private final Handler mHandler;
        private boolean mInLongPress;
        private boolean mIsDoubleTapping;
        private boolean mIsLongpressEnabled;
        private float mLastFocusX;
        private float mLastFocusY;
        final GestureDetector.OnGestureListener mListener;
        private int mMaximumFlingVelocity;
        private int mMinimumFlingVelocity;
        private MotionEvent mPreviousUpEvent;
        boolean mStillDown;
        private int mTouchSlopSquare;
        private VelocityTracker mVelocityTracker;
        private static final int TAP_TIMEOUT = ViewConfiguration.getTapTimeout();
        private static final int DOUBLE_TAP_TIMEOUT = ViewConfiguration.getDoubleTapTimeout();

        /* loaded from: classes.dex */
        private class GestureHandler extends Handler {
            GestureHandler() {
            }

            GestureHandler(Handler handler) {
                super(handler.getLooper());
            }

            @Override // android.os.Handler
            public void handleMessage(Message msg) {
                switch (msg.what) {
                    case 1:
                        GestureDetectorCompatImplBase.this.mListener.onShowPress(GestureDetectorCompatImplBase.this.mCurrentDownEvent);
                        return;
                    case 2:
                        GestureDetectorCompatImplBase.this.dispatchLongPress();
                        return;
                    case 3:
                        if (GestureDetectorCompatImplBase.this.mDoubleTapListener != null) {
                            if (!GestureDetectorCompatImplBase.this.mStillDown) {
                                GestureDetectorCompatImplBase.this.mDoubleTapListener.onSingleTapConfirmed(GestureDetectorCompatImplBase.this.mCurrentDownEvent);
                                return;
                            } else {
                                GestureDetectorCompatImplBase.this.mDeferConfirmSingleTap = true;
                                return;
                            }
                        }
                        return;
                    default:
                        throw new RuntimeException("Unknown message " + msg);
                }
            }
        }

        GestureDetectorCompatImplBase(Context context, GestureDetector.OnGestureListener listener, Handler handler) {
            if (handler != null) {
                this.mHandler = new GestureHandler(handler);
            } else {
                this.mHandler = new GestureHandler();
            }
            this.mListener = listener;
            if (listener instanceof GestureDetector.OnDoubleTapListener) {
                setOnDoubleTapListener((GestureDetector.OnDoubleTapListener) listener);
            }
            init(context);
        }

        private void init(Context context) {
            if (context == null) {
                throw new IllegalArgumentException("Context must not be null");
            }
            if (this.mListener == null) {
                throw new IllegalArgumentException("OnGestureListener must not be null");
            }
            this.mIsLongpressEnabled = true;
            ViewConfiguration configuration = ViewConfiguration.get(context);
            int touchSlop = configuration.getScaledTouchSlop();
            int doubleTapSlop = configuration.getScaledDoubleTapSlop();
            this.mMinimumFlingVelocity = configuration.getScaledMinimumFlingVelocity();
            this.mMaximumFlingVelocity = configuration.getScaledMaximumFlingVelocity();
            this.mTouchSlopSquare = touchSlop * touchSlop;
            this.mDoubleTapSlopSquare = doubleTapSlop * doubleTapSlop;
        }

        @Override // androidx.core.view.GestureDetectorCompat.GestureDetectorCompatImpl
        public void setOnDoubleTapListener(GestureDetector.OnDoubleTapListener onDoubleTapListener) {
            this.mDoubleTapListener = onDoubleTapListener;
        }

        @Override // androidx.core.view.GestureDetectorCompat.GestureDetectorCompatImpl
        public void setIsLongpressEnabled(boolean isLongpressEnabled) {
            this.mIsLongpressEnabled = isLongpressEnabled;
        }

        @Override // androidx.core.view.GestureDetectorCompat.GestureDetectorCompatImpl
        public boolean isLongpressEnabled() {
            return this.mIsLongpressEnabled;
        }

        @Override // androidx.core.view.GestureDetectorCompat.GestureDetectorCompatImpl
        public boolean onTouchEvent(MotionEvent ev) {
            MotionEvent motionEvent;
            GestureDetector.OnDoubleTapListener onDoubleTapListener;
            boolean pointerUp;
            int skipIndex;
            int upIndex;
            int action = ev.getAction();
            if (this.mVelocityTracker == null) {
                this.mVelocityTracker = VelocityTracker.obtain();
            }
            this.mVelocityTracker.addMovement(ev);
            boolean pointerUp2 = (action & 255) == 6;
            int skipIndex2 = pointerUp2 ? ev.getActionIndex() : -1;
            float sumX = 0.0f;
            float sumY = 0.0f;
            int count = ev.getPointerCount();
            for (int i = 0; i < count; i++) {
                if (skipIndex2 != i) {
                    sumX += ev.getX(i);
                    sumY += ev.getY(i);
                }
            }
            int div = pointerUp2 ? count - 1 : count;
            float focusX = sumX / div;
            float focusY = sumY / div;
            boolean handled = false;
            switch (action & 255) {
                case 0:
                    if (this.mDoubleTapListener != null) {
                        boolean hadTapMessage = this.mHandler.hasMessages(3);
                        if (hadTapMessage) {
                            this.mHandler.removeMessages(3);
                        }
                        MotionEvent motionEvent2 = this.mCurrentDownEvent;
                        if (motionEvent2 != null && (motionEvent = this.mPreviousUpEvent) != null && hadTapMessage && isConsideredDoubleTap(motionEvent2, motionEvent, ev)) {
                            this.mIsDoubleTapping = true;
                            handled = this.mDoubleTapListener.onDoubleTap(this.mCurrentDownEvent) | false | this.mDoubleTapListener.onDoubleTapEvent(ev);
                        } else {
                            this.mHandler.sendEmptyMessageDelayed(3, DOUBLE_TAP_TIMEOUT);
                        }
                    }
                    this.mLastFocusX = focusX;
                    this.mDownFocusX = focusX;
                    this.mLastFocusY = focusY;
                    this.mDownFocusY = focusY;
                    MotionEvent motionEvent3 = this.mCurrentDownEvent;
                    if (motionEvent3 != null) {
                        motionEvent3.recycle();
                    }
                    this.mCurrentDownEvent = MotionEvent.obtain(ev);
                    this.mAlwaysInTapRegion = true;
                    this.mAlwaysInBiggerTapRegion = true;
                    this.mStillDown = true;
                    this.mInLongPress = false;
                    this.mDeferConfirmSingleTap = false;
                    if (this.mIsLongpressEnabled) {
                        this.mHandler.removeMessages(2);
                        this.mHandler.sendEmptyMessageAtTime(2, this.mCurrentDownEvent.getDownTime() + TAP_TIMEOUT + ViewConfiguration.getLongPressTimeout());
                    }
                    this.mHandler.sendEmptyMessageAtTime(1, this.mCurrentDownEvent.getDownTime() + TAP_TIMEOUT);
                    return handled | this.mListener.onDown(ev);
                case 1:
                    this.mStillDown = false;
                    MotionEvent currentUpEvent = MotionEvent.obtain(ev);
                    if (this.mIsDoubleTapping) {
                        handled = false | this.mDoubleTapListener.onDoubleTapEvent(ev);
                    } else if (this.mInLongPress) {
                        this.mHandler.removeMessages(3);
                        this.mInLongPress = false;
                    } else if (this.mAlwaysInTapRegion) {
                        handled = this.mListener.onSingleTapUp(ev);
                        if (this.mDeferConfirmSingleTap && (onDoubleTapListener = this.mDoubleTapListener) != null) {
                            onDoubleTapListener.onSingleTapConfirmed(ev);
                        }
                    } else {
                        VelocityTracker velocityTracker = this.mVelocityTracker;
                        int pointerId = ev.getPointerId(0);
                        velocityTracker.computeCurrentVelocity(1000, this.mMaximumFlingVelocity);
                        float velocityY = velocityTracker.getYVelocity(pointerId);
                        float velocityX = velocityTracker.getXVelocity(pointerId);
                        if (Math.abs(velocityY) > this.mMinimumFlingVelocity || Math.abs(velocityX) > this.mMinimumFlingVelocity) {
                            handled = this.mListener.onFling(this.mCurrentDownEvent, ev, velocityX, velocityY);
                        }
                    }
                    MotionEvent motionEvent4 = this.mPreviousUpEvent;
                    if (motionEvent4 != null) {
                        motionEvent4.recycle();
                    }
                    this.mPreviousUpEvent = currentUpEvent;
                    VelocityTracker velocityTracker2 = this.mVelocityTracker;
                    if (velocityTracker2 != null) {
                        velocityTracker2.recycle();
                        this.mVelocityTracker = null;
                    }
                    this.mIsDoubleTapping = false;
                    this.mDeferConfirmSingleTap = false;
                    this.mHandler.removeMessages(1);
                    this.mHandler.removeMessages(2);
                    return handled;
                case 2:
                    if (this.mInLongPress) {
                        return false;
                    }
                    float scrollX = this.mLastFocusX - focusX;
                    float scrollY = this.mLastFocusY - focusY;
                    if (this.mIsDoubleTapping) {
                        return false | this.mDoubleTapListener.onDoubleTapEvent(ev);
                    }
                    if (!this.mAlwaysInTapRegion) {
                        if (Math.abs(scrollX) >= 1.0f || Math.abs(scrollY) >= 1.0f) {
                            boolean handled2 = this.mListener.onScroll(this.mCurrentDownEvent, ev, scrollX, scrollY);
                            this.mLastFocusX = focusX;
                            this.mLastFocusY = focusY;
                            return handled2;
                        }
                        return false;
                    }
                    int deltaX = (int) (focusX - this.mDownFocusX);
                    int deltaY = (int) (focusY - this.mDownFocusY);
                    int distance = (deltaX * deltaX) + (deltaY * deltaY);
                    if (distance > this.mTouchSlopSquare) {
                        boolean handled3 = this.mListener.onScroll(this.mCurrentDownEvent, ev, scrollX, scrollY);
                        this.mLastFocusX = focusX;
                        this.mLastFocusY = focusY;
                        this.mAlwaysInTapRegion = false;
                        this.mHandler.removeMessages(3);
                        this.mHandler.removeMessages(1);
                        this.mHandler.removeMessages(2);
                        handled = handled3;
                    }
                    if (distance > this.mTouchSlopSquare) {
                        this.mAlwaysInBiggerTapRegion = false;
                        return handled;
                    }
                    return handled;
                case 3:
                    cancel();
                    return false;
                case 4:
                default:
                    return false;
                case 5:
                    this.mLastFocusX = focusX;
                    this.mDownFocusX = focusX;
                    this.mLastFocusY = focusY;
                    this.mDownFocusY = focusY;
                    cancelTaps();
                    return false;
                case 6:
                    this.mLastFocusX = focusX;
                    this.mDownFocusX = focusX;
                    this.mLastFocusY = focusY;
                    this.mDownFocusY = focusY;
                    this.mVelocityTracker.computeCurrentVelocity(1000, this.mMaximumFlingVelocity);
                    int upIndex2 = ev.getActionIndex();
                    int id1 = ev.getPointerId(upIndex2);
                    float x1 = this.mVelocityTracker.getXVelocity(id1);
                    float y1 = this.mVelocityTracker.getYVelocity(id1);
                    int action2 = 0;
                    while (action2 < count) {
                        if (action2 == upIndex2) {
                            pointerUp = pointerUp2;
                            skipIndex = skipIndex2;
                            upIndex = upIndex2;
                        } else {
                            pointerUp = pointerUp2;
                            int id2 = ev.getPointerId(action2);
                            skipIndex = skipIndex2;
                            float x = this.mVelocityTracker.getXVelocity(id2) * x1;
                            upIndex = upIndex2;
                            float y = this.mVelocityTracker.getYVelocity(id2) * y1;
                            float dot = x + y;
                            if (dot < 0.0f) {
                                this.mVelocityTracker.clear();
                                return false;
                            }
                        }
                        action2++;
                        upIndex2 = upIndex;
                        pointerUp2 = pointerUp;
                        skipIndex2 = skipIndex;
                    }
                    return false;
            }
        }

        private void cancel() {
            this.mHandler.removeMessages(1);
            this.mHandler.removeMessages(2);
            this.mHandler.removeMessages(3);
            this.mVelocityTracker.recycle();
            this.mVelocityTracker = null;
            this.mIsDoubleTapping = false;
            this.mStillDown = false;
            this.mAlwaysInTapRegion = false;
            this.mAlwaysInBiggerTapRegion = false;
            this.mDeferConfirmSingleTap = false;
            if (this.mInLongPress) {
                this.mInLongPress = false;
            }
        }

        private void cancelTaps() {
            this.mHandler.removeMessages(1);
            this.mHandler.removeMessages(2);
            this.mHandler.removeMessages(3);
            this.mIsDoubleTapping = false;
            this.mAlwaysInTapRegion = false;
            this.mAlwaysInBiggerTapRegion = false;
            this.mDeferConfirmSingleTap = false;
            if (this.mInLongPress) {
                this.mInLongPress = false;
            }
        }

        private boolean isConsideredDoubleTap(MotionEvent firstDown, MotionEvent firstUp, MotionEvent secondDown) {
            if (this.mAlwaysInBiggerTapRegion && secondDown.getEventTime() - firstUp.getEventTime() <= DOUBLE_TAP_TIMEOUT) {
                int deltaX = ((int) firstDown.getX()) - ((int) secondDown.getX());
                int deltaY = ((int) firstDown.getY()) - ((int) secondDown.getY());
                return (deltaX * deltaX) + (deltaY * deltaY) < this.mDoubleTapSlopSquare;
            }
            return false;
        }

        void dispatchLongPress() {
            this.mHandler.removeMessages(3);
            this.mDeferConfirmSingleTap = false;
            this.mInLongPress = true;
            this.mListener.onLongPress(this.mCurrentDownEvent);
        }
    }

    /* loaded from: classes.dex */
    static class GestureDetectorCompatImplJellybeanMr2 implements GestureDetectorCompatImpl {
        private final GestureDetector mDetector;

        GestureDetectorCompatImplJellybeanMr2(Context context, GestureDetector.OnGestureListener listener, Handler handler) {
            this.mDetector = new GestureDetector(context, listener, handler);
        }

        @Override // androidx.core.view.GestureDetectorCompat.GestureDetectorCompatImpl
        public boolean isLongpressEnabled() {
            return this.mDetector.isLongpressEnabled();
        }

        @Override // androidx.core.view.GestureDetectorCompat.GestureDetectorCompatImpl
        public boolean onTouchEvent(MotionEvent ev) {
            return this.mDetector.onTouchEvent(ev);
        }

        @Override // androidx.core.view.GestureDetectorCompat.GestureDetectorCompatImpl
        public void setIsLongpressEnabled(boolean enabled) {
            this.mDetector.setIsLongpressEnabled(enabled);
        }

        @Override // androidx.core.view.GestureDetectorCompat.GestureDetectorCompatImpl
        public void setOnDoubleTapListener(GestureDetector.OnDoubleTapListener listener) {
            this.mDetector.setOnDoubleTapListener(listener);
        }
    }

    public GestureDetectorCompat(Context context, GestureDetector.OnGestureListener listener) {
        this(context, listener, null);
    }

    public GestureDetectorCompat(Context context, GestureDetector.OnGestureListener listener, Handler handler) {
        if (Build.VERSION.SDK_INT > 17) {
            this.mImpl = new GestureDetectorCompatImplJellybeanMr2(context, listener, handler);
        } else {
            this.mImpl = new GestureDetectorCompatImplBase(context, listener, handler);
        }
    }

    public boolean isLongpressEnabled() {
        return this.mImpl.isLongpressEnabled();
    }

    public boolean onTouchEvent(MotionEvent event) {
        return this.mImpl.onTouchEvent(event);
    }

    public void setIsLongpressEnabled(boolean enabled) {
        this.mImpl.setIsLongpressEnabled(enabled);
    }

    public void setOnDoubleTapListener(GestureDetector.OnDoubleTapListener listener) {
        this.mImpl.setOnDoubleTapListener(listener);
    }
}
