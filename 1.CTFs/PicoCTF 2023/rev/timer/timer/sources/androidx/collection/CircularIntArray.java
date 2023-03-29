package androidx.collection;
/* loaded from: classes.dex */
public final class CircularIntArray {
    private int mCapacityBitmask;
    private int[] mElements;
    private int mHead;
    private int mTail;

    private void doubleCapacity() {
        int[] iArr = this.mElements;
        int n = iArr.length;
        int i = this.mHead;
        int r = n - i;
        int newCapacity = n << 1;
        if (newCapacity < 0) {
            throw new RuntimeException("Max array capacity exceeded");
        }
        int[] a = new int[newCapacity];
        System.arraycopy(iArr, i, a, 0, r);
        System.arraycopy(this.mElements, 0, a, r, this.mHead);
        this.mElements = a;
        this.mHead = 0;
        this.mTail = n;
        this.mCapacityBitmask = newCapacity - 1;
    }

    public CircularIntArray() {
        this(8);
    }

    public CircularIntArray(int minCapacity) {
        int arrayCapacity;
        if (minCapacity < 1) {
            throw new IllegalArgumentException("capacity must be >= 1");
        }
        if (minCapacity <= 1073741824) {
            if (Integer.bitCount(minCapacity) != 1) {
                arrayCapacity = Integer.highestOneBit(minCapacity - 1) << 1;
            } else {
                arrayCapacity = minCapacity;
            }
            this.mCapacityBitmask = arrayCapacity - 1;
            this.mElements = new int[arrayCapacity];
            return;
        }
        throw new IllegalArgumentException("capacity must be <= 2^30");
    }

    public void addFirst(int e) {
        int i = (this.mHead - 1) & this.mCapacityBitmask;
        this.mHead = i;
        this.mElements[i] = e;
        if (i == this.mTail) {
            doubleCapacity();
        }
    }

    public void addLast(int e) {
        int[] iArr = this.mElements;
        int i = this.mTail;
        iArr[i] = e;
        int i2 = this.mCapacityBitmask & (i + 1);
        this.mTail = i2;
        if (i2 == this.mHead) {
            doubleCapacity();
        }
    }

    public int popFirst() {
        int i = this.mHead;
        if (i == this.mTail) {
            throw new ArrayIndexOutOfBoundsException();
        }
        int result = this.mElements[i];
        this.mHead = (i + 1) & this.mCapacityBitmask;
        return result;
    }

    public int popLast() {
        int i = this.mHead;
        int i2 = this.mTail;
        if (i == i2) {
            throw new ArrayIndexOutOfBoundsException();
        }
        int t = this.mCapacityBitmask & (i2 - 1);
        int result = this.mElements[t];
        this.mTail = t;
        return result;
    }

    public void clear() {
        this.mTail = this.mHead;
    }

    public void removeFromStart(int numOfElements) {
        if (numOfElements <= 0) {
            return;
        }
        if (numOfElements > size()) {
            throw new ArrayIndexOutOfBoundsException();
        }
        this.mHead = (this.mHead + numOfElements) & this.mCapacityBitmask;
    }

    public void removeFromEnd(int numOfElements) {
        if (numOfElements <= 0) {
            return;
        }
        if (numOfElements > size()) {
            throw new ArrayIndexOutOfBoundsException();
        }
        this.mTail = (this.mTail - numOfElements) & this.mCapacityBitmask;
    }

    public int getFirst() {
        int i = this.mHead;
        if (i == this.mTail) {
            throw new ArrayIndexOutOfBoundsException();
        }
        return this.mElements[i];
    }

    public int getLast() {
        int i = this.mHead;
        int i2 = this.mTail;
        if (i == i2) {
            throw new ArrayIndexOutOfBoundsException();
        }
        return this.mElements[(i2 - 1) & this.mCapacityBitmask];
    }

    public int get(int n) {
        if (n < 0 || n >= size()) {
            throw new ArrayIndexOutOfBoundsException();
        }
        return this.mElements[(this.mHead + n) & this.mCapacityBitmask];
    }

    public int size() {
        return (this.mTail - this.mHead) & this.mCapacityBitmask;
    }

    public boolean isEmpty() {
        return this.mHead == this.mTail;
    }
}
