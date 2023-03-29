package androidx.recyclerview.widget;
/* loaded from: classes.dex */
public class BatchingListUpdateCallback implements ListUpdateCallback {
    private static final int TYPE_ADD = 1;
    private static final int TYPE_CHANGE = 3;
    private static final int TYPE_NONE = 0;
    private static final int TYPE_REMOVE = 2;
    final ListUpdateCallback mWrapped;
    int mLastEventType = 0;
    int mLastEventPosition = -1;
    int mLastEventCount = -1;
    Object mLastEventPayload = null;

    public BatchingListUpdateCallback(ListUpdateCallback callback) {
        this.mWrapped = callback;
    }

    public void dispatchLastEvent() {
        int i = this.mLastEventType;
        if (i == 0) {
            return;
        }
        switch (i) {
            case 1:
                this.mWrapped.onInserted(this.mLastEventPosition, this.mLastEventCount);
                break;
            case 2:
                this.mWrapped.onRemoved(this.mLastEventPosition, this.mLastEventCount);
                break;
            case 3:
                this.mWrapped.onChanged(this.mLastEventPosition, this.mLastEventCount, this.mLastEventPayload);
                break;
        }
        this.mLastEventPayload = null;
        this.mLastEventType = 0;
    }

    @Override // androidx.recyclerview.widget.ListUpdateCallback
    public void onInserted(int position, int count) {
        int i;
        if (this.mLastEventType == 1 && position >= (i = this.mLastEventPosition)) {
            int i2 = this.mLastEventCount;
            if (position <= i + i2) {
                this.mLastEventCount = i2 + count;
                this.mLastEventPosition = Math.min(position, i);
                return;
            }
        }
        dispatchLastEvent();
        this.mLastEventPosition = position;
        this.mLastEventCount = count;
        this.mLastEventType = 1;
    }

    @Override // androidx.recyclerview.widget.ListUpdateCallback
    public void onRemoved(int position, int count) {
        int i;
        if (this.mLastEventType == 2 && (i = this.mLastEventPosition) >= position && i <= position + count) {
            this.mLastEventCount += count;
            this.mLastEventPosition = position;
            return;
        }
        dispatchLastEvent();
        this.mLastEventPosition = position;
        this.mLastEventCount = count;
        this.mLastEventType = 2;
    }

    @Override // androidx.recyclerview.widget.ListUpdateCallback
    public void onMoved(int fromPosition, int toPosition) {
        dispatchLastEvent();
        this.mWrapped.onMoved(fromPosition, toPosition);
    }

    @Override // androidx.recyclerview.widget.ListUpdateCallback
    public void onChanged(int position, int count, Object payload) {
        if (this.mLastEventType == 3) {
            int i = this.mLastEventPosition;
            int i2 = this.mLastEventCount;
            if (position <= i + i2 && position + count >= i && this.mLastEventPayload == payload) {
                int previousEnd = i2 + i;
                this.mLastEventPosition = Math.min(position, i);
                this.mLastEventCount = Math.max(previousEnd, position + count) - this.mLastEventPosition;
                return;
            }
        }
        dispatchLastEvent();
        this.mLastEventPosition = position;
        this.mLastEventCount = count;
        this.mLastEventPayload = payload;
        this.mLastEventType = 3;
    }
}
