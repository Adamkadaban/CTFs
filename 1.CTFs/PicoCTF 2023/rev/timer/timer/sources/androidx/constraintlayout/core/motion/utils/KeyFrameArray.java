package androidx.constraintlayout.core.motion.utils;

import androidx.constraintlayout.core.motion.CustomAttribute;
import androidx.constraintlayout.core.motion.CustomVariable;
import java.io.PrintStream;
import java.util.Arrays;
/* loaded from: classes.dex */
public class KeyFrameArray {

    /* loaded from: classes.dex */
    public static class CustomArray {
        private static final int EMPTY = 999;
        int count;
        int[] keys = new int[101];
        CustomAttribute[] values = new CustomAttribute[101];

        public CustomArray() {
            clear();
        }

        public void clear() {
            Arrays.fill(this.keys, (int) EMPTY);
            Arrays.fill(this.values, (Object) null);
            this.count = 0;
        }

        public void dump() {
            PrintStream printStream = System.out;
            printStream.println("V: " + Arrays.toString(Arrays.copyOf(this.keys, this.count)));
            System.out.print("K: [");
            int i = 0;
            while (i < this.count) {
                PrintStream printStream2 = System.out;
                StringBuilder sb = new StringBuilder();
                sb.append(i == 0 ? "" : ", ");
                sb.append(valueAt(i));
                printStream2.print(sb.toString());
                i++;
            }
            System.out.println("]");
        }

        public int size() {
            return this.count;
        }

        public CustomAttribute valueAt(int i) {
            return this.values[this.keys[i]];
        }

        public int keyAt(int i) {
            return this.keys[i];
        }

        public void append(int position, CustomAttribute value) {
            if (this.values[position] != null) {
                remove(position);
            }
            this.values[position] = value;
            int[] iArr = this.keys;
            int i = this.count;
            this.count = i + 1;
            iArr[i] = position;
            Arrays.sort(iArr);
        }

        public void remove(int position) {
            this.values[position] = null;
            int j = 0;
            int i = 0;
            while (true) {
                int i2 = this.count;
                if (i < i2) {
                    int[] iArr = this.keys;
                    if (position == iArr[i]) {
                        iArr[i] = EMPTY;
                        j++;
                    }
                    if (i != j) {
                        iArr[i] = iArr[j];
                    }
                    j++;
                    i++;
                } else {
                    this.count = i2 - 1;
                    return;
                }
            }
        }
    }

    /* loaded from: classes.dex */
    public static class CustomVar {
        private static final int EMPTY = 999;
        int count;
        int[] keys = new int[101];
        CustomVariable[] values = new CustomVariable[101];

        public CustomVar() {
            clear();
        }

        public void clear() {
            Arrays.fill(this.keys, (int) EMPTY);
            Arrays.fill(this.values, (Object) null);
            this.count = 0;
        }

        public void dump() {
            PrintStream printStream = System.out;
            printStream.println("V: " + Arrays.toString(Arrays.copyOf(this.keys, this.count)));
            System.out.print("K: [");
            int i = 0;
            while (i < this.count) {
                PrintStream printStream2 = System.out;
                StringBuilder sb = new StringBuilder();
                sb.append(i == 0 ? "" : ", ");
                sb.append(valueAt(i));
                printStream2.print(sb.toString());
                i++;
            }
            System.out.println("]");
        }

        public int size() {
            return this.count;
        }

        public CustomVariable valueAt(int i) {
            return this.values[this.keys[i]];
        }

        public int keyAt(int i) {
            return this.keys[i];
        }

        public void append(int position, CustomVariable value) {
            if (this.values[position] != null) {
                remove(position);
            }
            this.values[position] = value;
            int[] iArr = this.keys;
            int i = this.count;
            this.count = i + 1;
            iArr[i] = position;
            Arrays.sort(iArr);
        }

        public void remove(int position) {
            this.values[position] = null;
            int j = 0;
            int i = 0;
            while (true) {
                int i2 = this.count;
                if (i < i2) {
                    int[] iArr = this.keys;
                    if (position == iArr[i]) {
                        iArr[i] = EMPTY;
                        j++;
                    }
                    if (i != j) {
                        iArr[i] = iArr[j];
                    }
                    j++;
                    i++;
                } else {
                    this.count = i2 - 1;
                    return;
                }
            }
        }
    }

    /* loaded from: classes.dex */
    static class FloatArray {
        private static final int EMPTY = 999;
        int count;
        int[] keys = new int[101];
        float[][] values = new float[101];

        public FloatArray() {
            clear();
        }

        public void clear() {
            Arrays.fill(this.keys, (int) EMPTY);
            Arrays.fill(this.values, (Object) null);
            this.count = 0;
        }

        public void dump() {
            PrintStream printStream = System.out;
            printStream.println("V: " + Arrays.toString(Arrays.copyOf(this.keys, this.count)));
            System.out.print("K: [");
            int i = 0;
            while (i < this.count) {
                PrintStream printStream2 = System.out;
                StringBuilder sb = new StringBuilder();
                sb.append(i == 0 ? "" : ", ");
                sb.append(Arrays.toString(valueAt(i)));
                printStream2.print(sb.toString());
                i++;
            }
            System.out.println("]");
        }

        public int size() {
            return this.count;
        }

        public float[] valueAt(int i) {
            return this.values[this.keys[i]];
        }

        public int keyAt(int i) {
            return this.keys[i];
        }

        public void append(int position, float[] value) {
            if (this.values[position] != null) {
                remove(position);
            }
            this.values[position] = value;
            int[] iArr = this.keys;
            int i = this.count;
            this.count = i + 1;
            iArr[i] = position;
            Arrays.sort(iArr);
        }

        public void remove(int position) {
            this.values[position] = null;
            int j = 0;
            int i = 0;
            while (true) {
                int i2 = this.count;
                if (i < i2) {
                    int[] iArr = this.keys;
                    if (position == iArr[i]) {
                        iArr[i] = EMPTY;
                        j++;
                    }
                    if (i != j) {
                        iArr[i] = iArr[j];
                    }
                    j++;
                    i++;
                } else {
                    this.count = i2 - 1;
                    return;
                }
            }
        }
    }
}
