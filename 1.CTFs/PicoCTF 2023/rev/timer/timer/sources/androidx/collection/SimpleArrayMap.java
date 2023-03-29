package androidx.collection;

import java.util.ConcurrentModificationException;
import java.util.Map;
/* loaded from: classes.dex */
public class SimpleArrayMap<K, V> {
    private static final int BASE_SIZE = 4;
    private static final int CACHE_SIZE = 10;
    private static final boolean CONCURRENT_MODIFICATION_EXCEPTIONS = true;
    private static final boolean DEBUG = false;
    private static final String TAG = "ArrayMap";
    static Object[] mBaseCache;
    static int mBaseCacheSize;
    static Object[] mTwiceBaseCache;
    static int mTwiceBaseCacheSize;
    Object[] mArray;
    int[] mHashes;
    int mSize;

    private static int binarySearchHashes(int[] hashes, int N, int hash) {
        try {
            return ContainerHelpers.binarySearch(hashes, N, hash);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ConcurrentModificationException();
        }
    }

    int indexOf(Object key, int hash) {
        int N = this.mSize;
        if (N == 0) {
            return -1;
        }
        int index = binarySearchHashes(this.mHashes, N, hash);
        if (index < 0) {
            return index;
        }
        if (key.equals(this.mArray[index << 1])) {
            return index;
        }
        int end = index + 1;
        while (end < N && this.mHashes[end] == hash) {
            if (key.equals(this.mArray[end << 1])) {
                return end;
            }
            end++;
        }
        for (int i = index - 1; i >= 0 && this.mHashes[i] == hash; i--) {
            if (key.equals(this.mArray[i << 1])) {
                return i;
            }
        }
        int i2 = ~end;
        return i2;
    }

    int indexOfNull() {
        int N = this.mSize;
        if (N == 0) {
            return -1;
        }
        int index = binarySearchHashes(this.mHashes, N, 0);
        if (index < 0) {
            return index;
        }
        if (this.mArray[index << 1] == null) {
            return index;
        }
        int end = index + 1;
        while (end < N && this.mHashes[end] == 0) {
            if (this.mArray[end << 1] == null) {
                return end;
            }
            end++;
        }
        for (int i = index - 1; i >= 0 && this.mHashes[i] == 0; i--) {
            if (this.mArray[i << 1] == null) {
                return i;
            }
        }
        int i2 = ~end;
        return i2;
    }

    private void allocArrays(int size) {
        if (size == 8) {
            synchronized (SimpleArrayMap.class) {
                Object[] array = mTwiceBaseCache;
                if (array != null) {
                    this.mArray = array;
                    mTwiceBaseCache = (Object[]) array[0];
                    this.mHashes = (int[]) array[1];
                    array[1] = null;
                    array[0] = null;
                    mTwiceBaseCacheSize--;
                    return;
                }
            }
        } else if (size == 4) {
            synchronized (SimpleArrayMap.class) {
                Object[] array2 = mBaseCache;
                if (array2 != null) {
                    this.mArray = array2;
                    mBaseCache = (Object[]) array2[0];
                    this.mHashes = (int[]) array2[1];
                    array2[1] = null;
                    array2[0] = null;
                    mBaseCacheSize--;
                    return;
                }
            }
        }
        this.mHashes = new int[size];
        this.mArray = new Object[size << 1];
    }

    private static void freeArrays(int[] hashes, Object[] array, int size) {
        if (hashes.length == 8) {
            synchronized (SimpleArrayMap.class) {
                if (mTwiceBaseCacheSize < 10) {
                    array[0] = mTwiceBaseCache;
                    array[1] = hashes;
                    for (int i = (size << 1) - 1; i >= 2; i--) {
                        array[i] = null;
                    }
                    mTwiceBaseCache = array;
                    mTwiceBaseCacheSize++;
                }
            }
        } else if (hashes.length == 4) {
            synchronized (SimpleArrayMap.class) {
                if (mBaseCacheSize < 10) {
                    array[0] = mBaseCache;
                    array[1] = hashes;
                    for (int i2 = (size << 1) - 1; i2 >= 2; i2--) {
                        array[i2] = null;
                    }
                    mBaseCache = array;
                    mBaseCacheSize++;
                }
            }
        }
    }

    public SimpleArrayMap() {
        this.mHashes = ContainerHelpers.EMPTY_INTS;
        this.mArray = ContainerHelpers.EMPTY_OBJECTS;
        this.mSize = 0;
    }

    public SimpleArrayMap(int capacity) {
        if (capacity == 0) {
            this.mHashes = ContainerHelpers.EMPTY_INTS;
            this.mArray = ContainerHelpers.EMPTY_OBJECTS;
        } else {
            allocArrays(capacity);
        }
        this.mSize = 0;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public SimpleArrayMap(SimpleArrayMap<K, V> map) {
        this();
        if (map != 0) {
            putAll(map);
        }
    }

    public void clear() {
        if (this.mSize > 0) {
            int[] ohashes = this.mHashes;
            Object[] oarray = this.mArray;
            int osize = this.mSize;
            this.mHashes = ContainerHelpers.EMPTY_INTS;
            this.mArray = ContainerHelpers.EMPTY_OBJECTS;
            this.mSize = 0;
            freeArrays(ohashes, oarray, osize);
        }
        if (this.mSize > 0) {
            throw new ConcurrentModificationException();
        }
    }

    public void ensureCapacity(int minimumCapacity) {
        int osize = this.mSize;
        if (this.mHashes.length < minimumCapacity) {
            int[] ohashes = this.mHashes;
            Object[] oarray = this.mArray;
            allocArrays(minimumCapacity);
            if (this.mSize > 0) {
                System.arraycopy(ohashes, 0, this.mHashes, 0, osize);
                System.arraycopy(oarray, 0, this.mArray, 0, osize << 1);
            }
            freeArrays(ohashes, oarray, osize);
        }
        if (this.mSize != osize) {
            throw new ConcurrentModificationException();
        }
    }

    public boolean containsKey(Object key) {
        if (indexOfKey(key) >= 0) {
            return CONCURRENT_MODIFICATION_EXCEPTIONS;
        }
        return false;
    }

    public int indexOfKey(Object key) {
        return key == null ? indexOfNull() : indexOf(key, key.hashCode());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int indexOfValue(Object value) {
        int N = this.mSize * 2;
        Object[] array = this.mArray;
        if (value == null) {
            for (int i = 1; i < N; i += 2) {
                if (array[i] == null) {
                    return i >> 1;
                }
            }
            return -1;
        }
        for (int i2 = 1; i2 < N; i2 += 2) {
            if (value.equals(array[i2])) {
                return i2 >> 1;
            }
        }
        return -1;
    }

    public boolean containsValue(Object value) {
        if (indexOfValue(value) >= 0) {
            return CONCURRENT_MODIFICATION_EXCEPTIONS;
        }
        return false;
    }

    public V get(Object key) {
        return getOrDefault(key, null);
    }

    public V getOrDefault(Object key, V defaultValue) {
        int index = indexOfKey(key);
        return index >= 0 ? (V) this.mArray[(index << 1) + 1] : defaultValue;
    }

    public K keyAt(int index) {
        return (K) this.mArray[index << 1];
    }

    public V valueAt(int index) {
        return (V) this.mArray[(index << 1) + 1];
    }

    public V setValueAt(int index, V value) {
        int index2 = (index << 1) + 1;
        Object[] objArr = this.mArray;
        V old = (V) objArr[index2];
        objArr[index2] = value;
        return old;
    }

    public boolean isEmpty() {
        if (this.mSize <= 0) {
            return CONCURRENT_MODIFICATION_EXCEPTIONS;
        }
        return false;
    }

    public V put(K key, V value) {
        int hash;
        int index;
        int osize = this.mSize;
        if (key == null) {
            hash = 0;
            index = indexOfNull();
        } else {
            hash = key.hashCode();
            index = indexOf(key, hash);
        }
        if (index >= 0) {
            int index2 = (index << 1) + 1;
            Object[] objArr = this.mArray;
            V old = (V) objArr[index2];
            objArr[index2] = value;
            return old;
        }
        int index3 = ~index;
        if (osize >= this.mHashes.length) {
            int n = 4;
            if (osize >= 8) {
                n = (osize >> 1) + osize;
            } else if (osize >= 4) {
                n = 8;
            }
            int[] ohashes = this.mHashes;
            Object[] oarray = this.mArray;
            allocArrays(n);
            if (osize != this.mSize) {
                throw new ConcurrentModificationException();
            }
            int[] iArr = this.mHashes;
            if (iArr.length > 0) {
                System.arraycopy(ohashes, 0, iArr, 0, ohashes.length);
                System.arraycopy(oarray, 0, this.mArray, 0, oarray.length);
            }
            freeArrays(ohashes, oarray, osize);
        }
        if (index3 < osize) {
            int[] iArr2 = this.mHashes;
            System.arraycopy(iArr2, index3, iArr2, index3 + 1, osize - index3);
            Object[] objArr2 = this.mArray;
            System.arraycopy(objArr2, index3 << 1, objArr2, (index3 + 1) << 1, (this.mSize - index3) << 1);
        }
        int i = this.mSize;
        if (osize == i) {
            int[] iArr3 = this.mHashes;
            if (index3 < iArr3.length) {
                iArr3[index3] = hash;
                Object[] objArr3 = this.mArray;
                objArr3[index3 << 1] = key;
                objArr3[(index3 << 1) + 1] = value;
                this.mSize = i + 1;
                return null;
            }
        }
        throw new ConcurrentModificationException();
    }

    public void putAll(SimpleArrayMap<? extends K, ? extends V> array) {
        int N = array.mSize;
        ensureCapacity(this.mSize + N);
        if (this.mSize == 0) {
            if (N > 0) {
                System.arraycopy(array.mHashes, 0, this.mHashes, 0, N);
                System.arraycopy(array.mArray, 0, this.mArray, 0, N << 1);
                this.mSize = N;
                return;
            }
            return;
        }
        for (int i = 0; i < N; i++) {
            put(array.keyAt(i), array.valueAt(i));
        }
    }

    public V putIfAbsent(K key, V value) {
        V mapValue = get(key);
        if (mapValue == null) {
            return put(key, value);
        }
        return mapValue;
    }

    public V remove(Object key) {
        int index = indexOfKey(key);
        if (index >= 0) {
            return removeAt(index);
        }
        return null;
    }

    public boolean remove(Object key, Object value) {
        int index = indexOfKey(key);
        if (index >= 0) {
            V mapValue = valueAt(index);
            if (value == mapValue || (value != null && value.equals(mapValue))) {
                removeAt(index);
                return CONCURRENT_MODIFICATION_EXCEPTIONS;
            }
            return false;
        }
        return false;
    }

    public V removeAt(int index) {
        int nsize;
        Object[] objArr = this.mArray;
        V v = (V) objArr[(index << 1) + 1];
        int osize = this.mSize;
        if (osize <= 1) {
            freeArrays(this.mHashes, objArr, osize);
            this.mHashes = ContainerHelpers.EMPTY_INTS;
            this.mArray = ContainerHelpers.EMPTY_OBJECTS;
            nsize = 0;
        } else {
            nsize = osize - 1;
            int[] iArr = this.mHashes;
            if (iArr.length > 8 && this.mSize < iArr.length / 3) {
                int n = osize > 8 ? osize + (osize >> 1) : 8;
                int[] ohashes = this.mHashes;
                Object[] oarray = this.mArray;
                allocArrays(n);
                if (osize != this.mSize) {
                    throw new ConcurrentModificationException();
                }
                if (index > 0) {
                    System.arraycopy(ohashes, 0, this.mHashes, 0, index);
                    System.arraycopy(oarray, 0, this.mArray, 0, index << 1);
                }
                if (index < nsize) {
                    System.arraycopy(ohashes, index + 1, this.mHashes, index, nsize - index);
                    System.arraycopy(oarray, (index + 1) << 1, this.mArray, index << 1, (nsize - index) << 1);
                }
            } else {
                if (index < nsize) {
                    System.arraycopy(iArr, index + 1, iArr, index, nsize - index);
                    Object[] objArr2 = this.mArray;
                    System.arraycopy(objArr2, (index + 1) << 1, objArr2, index << 1, (nsize - index) << 1);
                }
                Object[] objArr3 = this.mArray;
                objArr3[nsize << 1] = null;
                objArr3[(nsize << 1) + 1] = null;
            }
        }
        if (osize != this.mSize) {
            throw new ConcurrentModificationException();
        }
        this.mSize = nsize;
        return v;
    }

    public V replace(K key, V value) {
        int index = indexOfKey(key);
        if (index >= 0) {
            return setValueAt(index, value);
        }
        return null;
    }

    public boolean replace(K key, V oldValue, V newValue) {
        int index = indexOfKey(key);
        if (index >= 0) {
            V mapValue = valueAt(index);
            if (mapValue == oldValue || (oldValue != null && oldValue.equals(mapValue))) {
                setValueAt(index, newValue);
                return CONCURRENT_MODIFICATION_EXCEPTIONS;
            }
            return false;
        }
        return false;
    }

    public int size() {
        return this.mSize;
    }

    public boolean equals(Object object) {
        if (this == object) {
            return CONCURRENT_MODIFICATION_EXCEPTIONS;
        }
        if (object instanceof SimpleArrayMap) {
            SimpleArrayMap<?, ?> map = (SimpleArrayMap) object;
            if (size() != map.size()) {
                return false;
            }
            for (int i = 0; i < this.mSize; i++) {
                try {
                    K key = keyAt(i);
                    V mine = valueAt(i);
                    Object theirs = map.get(key);
                    if (mine == null) {
                        if (theirs != null || !map.containsKey(key)) {
                            return false;
                        }
                    } else if (!mine.equals(theirs)) {
                        return false;
                    }
                } catch (ClassCastException e) {
                    return false;
                } catch (NullPointerException e2) {
                    return false;
                }
            }
            return CONCURRENT_MODIFICATION_EXCEPTIONS;
        } else if (object instanceof Map) {
            Map<?, ?> map2 = (Map) object;
            if (size() != map2.size()) {
                return false;
            }
            for (int i2 = 0; i2 < this.mSize; i2++) {
                try {
                    K key2 = keyAt(i2);
                    V mine2 = valueAt(i2);
                    Object theirs2 = map2.get(key2);
                    if (mine2 == null) {
                        if (theirs2 != null || !map2.containsKey(key2)) {
                            return false;
                        }
                    } else if (!mine2.equals(theirs2)) {
                        return false;
                    }
                } catch (ClassCastException e3) {
                    return false;
                } catch (NullPointerException e4) {
                    return false;
                }
            }
            return CONCURRENT_MODIFICATION_EXCEPTIONS;
        } else {
            return false;
        }
    }

    public int hashCode() {
        int[] hashes = this.mHashes;
        Object[] array = this.mArray;
        int result = 0;
        int i = 0;
        int v = 1;
        int s = this.mSize;
        while (i < s) {
            Object value = array[v];
            result += hashes[i] ^ (value == null ? 0 : value.hashCode());
            i++;
            v += 2;
        }
        return result;
    }

    public String toString() {
        if (isEmpty()) {
            return "{}";
        }
        StringBuilder buffer = new StringBuilder(this.mSize * 28);
        buffer.append('{');
        for (int i = 0; i < this.mSize; i++) {
            if (i > 0) {
                buffer.append(", ");
            }
            Object key = keyAt(i);
            if (key != this) {
                buffer.append(key);
            } else {
                buffer.append("(this Map)");
            }
            buffer.append('=');
            Object value = valueAt(i);
            if (value != this) {
                buffer.append(value);
            } else {
                buffer.append("(this Map)");
            }
        }
        buffer.append('}');
        return buffer.toString();
    }
}
