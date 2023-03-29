package androidx.constraintlayout.core.motion.utils;

import java.util.Arrays;
/* loaded from: classes.dex */
public class TypedBundle {
    private static final int INITIAL_BOOLEAN = 4;
    private static final int INITIAL_FLOAT = 10;
    private static final int INITIAL_INT = 10;
    private static final int INITIAL_STRING = 5;
    int[] mTypeInt = new int[10];
    int[] mValueInt = new int[10];
    int mCountInt = 0;
    int[] mTypeFloat = new int[10];
    float[] mValueFloat = new float[10];
    int mCountFloat = 0;
    int[] mTypeString = new int[5];
    String[] mValueString = new String[5];
    int mCountString = 0;
    int[] mTypeBoolean = new int[4];
    boolean[] mValueBoolean = new boolean[4];
    int mCountBoolean = 0;

    public int getInteger(int type) {
        for (int i = 0; i < this.mCountInt; i++) {
            if (this.mTypeInt[i] == type) {
                return this.mValueInt[i];
            }
        }
        return -1;
    }

    public void add(int type, int value) {
        int i = this.mCountInt;
        int[] iArr = this.mTypeInt;
        if (i >= iArr.length) {
            this.mTypeInt = Arrays.copyOf(iArr, iArr.length * 2);
            int[] iArr2 = this.mValueInt;
            this.mValueInt = Arrays.copyOf(iArr2, iArr2.length * 2);
        }
        int[] iArr3 = this.mTypeInt;
        int i2 = this.mCountInt;
        iArr3[i2] = type;
        int[] iArr4 = this.mValueInt;
        this.mCountInt = i2 + 1;
        iArr4[i2] = value;
    }

    public void add(int type, float value) {
        int i = this.mCountFloat;
        int[] iArr = this.mTypeFloat;
        if (i >= iArr.length) {
            this.mTypeFloat = Arrays.copyOf(iArr, iArr.length * 2);
            float[] fArr = this.mValueFloat;
            this.mValueFloat = Arrays.copyOf(fArr, fArr.length * 2);
        }
        int[] iArr2 = this.mTypeFloat;
        int i2 = this.mCountFloat;
        iArr2[i2] = type;
        float[] fArr2 = this.mValueFloat;
        this.mCountFloat = i2 + 1;
        fArr2[i2] = value;
    }

    public void addIfNotNull(int type, String value) {
        if (value != null) {
            add(type, value);
        }
    }

    public void add(int type, String value) {
        int i = this.mCountString;
        int[] iArr = this.mTypeString;
        if (i >= iArr.length) {
            this.mTypeString = Arrays.copyOf(iArr, iArr.length * 2);
            String[] strArr = this.mValueString;
            this.mValueString = (String[]) Arrays.copyOf(strArr, strArr.length * 2);
        }
        int[] iArr2 = this.mTypeString;
        int i2 = this.mCountString;
        iArr2[i2] = type;
        String[] strArr2 = this.mValueString;
        this.mCountString = i2 + 1;
        strArr2[i2] = value;
    }

    public void add(int type, boolean value) {
        int i = this.mCountBoolean;
        int[] iArr = this.mTypeBoolean;
        if (i >= iArr.length) {
            this.mTypeBoolean = Arrays.copyOf(iArr, iArr.length * 2);
            boolean[] zArr = this.mValueBoolean;
            this.mValueBoolean = Arrays.copyOf(zArr, zArr.length * 2);
        }
        int[] iArr2 = this.mTypeBoolean;
        int i2 = this.mCountBoolean;
        iArr2[i2] = type;
        boolean[] zArr2 = this.mValueBoolean;
        this.mCountBoolean = i2 + 1;
        zArr2[i2] = value;
    }

    public void applyDelta(TypedValues values) {
        for (int i = 0; i < this.mCountInt; i++) {
            values.setValue(this.mTypeInt[i], this.mValueInt[i]);
        }
        for (int i2 = 0; i2 < this.mCountFloat; i2++) {
            values.setValue(this.mTypeFloat[i2], this.mValueFloat[i2]);
        }
        for (int i3 = 0; i3 < this.mCountString; i3++) {
            values.setValue(this.mTypeString[i3], this.mValueString[i3]);
        }
        for (int i4 = 0; i4 < this.mCountBoolean; i4++) {
            values.setValue(this.mTypeBoolean[i4], this.mValueBoolean[i4]);
        }
    }

    public void applyDelta(TypedBundle values) {
        for (int i = 0; i < this.mCountInt; i++) {
            values.add(this.mTypeInt[i], this.mValueInt[i]);
        }
        for (int i2 = 0; i2 < this.mCountFloat; i2++) {
            values.add(this.mTypeFloat[i2], this.mValueFloat[i2]);
        }
        for (int i3 = 0; i3 < this.mCountString; i3++) {
            values.add(this.mTypeString[i3], this.mValueString[i3]);
        }
        for (int i4 = 0; i4 < this.mCountBoolean; i4++) {
            values.add(this.mTypeBoolean[i4], this.mValueBoolean[i4]);
        }
    }

    public void clear() {
        this.mCountBoolean = 0;
        this.mCountString = 0;
        this.mCountFloat = 0;
        this.mCountInt = 0;
    }
}
