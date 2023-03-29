package kotlin;
/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: FloorDivMod.kt */
@Metadata(d1 = {"\u0000 \n\u0000\n\u0002\u0010\b\n\u0002\u0010\u0005\n\u0000\n\u0002\u0010\t\n\u0002\u0010\n\n\u0000\n\u0002\u0010\u0006\n\u0002\u0010\u0007\n\u0000\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0002H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0001H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0004*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0005H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0002H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0001H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0004*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0005H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0004*\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0004*\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0001H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0004*\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0004*\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0005H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u0002H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u0001H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0004*\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u0005H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0002*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0002H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0001H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0004*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0005*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0005H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0007*\u00020\u00072\u0006\u0010\u0003\u001a\u00020\u0007H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0007*\u00020\u00072\u0006\u0010\u0003\u001a\u00020\bH\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0007*\u00020\b2\u0006\u0010\u0003\u001a\u00020\u0007H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\b*\u00020\b2\u0006\u0010\u0003\u001a\u00020\bH\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0002*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0002H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0001H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0004*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0005*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0005H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0002*\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0001*\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0001H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0004*\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0005*\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0005H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0002*\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u0002H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0001*\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u0001H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0004*\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u0004H\u0087\b\u001a\u0015\u0010\u0006\u001a\u00020\u0005*\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u0005H\u0087\b¨\u0006\t"}, d2 = {"floorDiv", "", "", "other", "", "", "mod", "", "", "kotlin-stdlib"}, k = 5, mv = {1, 6, 0}, xi = 49, xs = "kotlin/NumbersKt")
/* loaded from: classes.dex */
public class NumbersKt__FloorDivModKt extends NumbersKt__BigIntegersKt {
    private static final int floorDiv(byte $this$floorDiv, byte other) {
        int i = $this$floorDiv / other;
        return (($this$floorDiv ^ other) >= 0 || i * other == $this$floorDiv) ? i : i - 1;
    }

    private static final byte mod(byte $this$mod, byte other) {
        int i = $this$mod % other;
        return (byte) (i + ((((i ^ other) & ((-i) | i)) >> 31) & other));
    }

    private static final int floorDiv(byte $this$floorDiv, short other) {
        int i = $this$floorDiv / other;
        return (($this$floorDiv ^ other) >= 0 || i * other == $this$floorDiv) ? i : i - 1;
    }

    private static final short mod(byte $this$mod, short other) {
        int i = $this$mod % other;
        return (short) (i + ((((i ^ other) & ((-i) | i)) >> 31) & other));
    }

    private static final int floorDiv(byte $this$floorDiv, int other) {
        int i = $this$floorDiv / other;
        return (($this$floorDiv ^ other) >= 0 || i * other == $this$floorDiv) ? i : i - 1;
    }

    private static final int mod(byte $this$mod, int other) {
        int i = $this$mod % other;
        return i + ((((i ^ other) & ((-i) | i)) >> 31) & other);
    }

    private static final long floorDiv(byte $this$floorDiv, long other) {
        long j = $this$floorDiv;
        long j2 = j / other;
        return ((j ^ other) >= 0 || j2 * other == j) ? j2 : j2 - 1;
    }

    private static final long mod(byte $this$mod, long other) {
        long j = $this$mod % other;
        return j + ((((j ^ other) & ((-j) | j)) >> 63) & other);
    }

    private static final int floorDiv(short $this$floorDiv, byte other) {
        int i = $this$floorDiv / other;
        return (($this$floorDiv ^ other) >= 0 || i * other == $this$floorDiv) ? i : i - 1;
    }

    private static final byte mod(short $this$mod, byte other) {
        int i = $this$mod % other;
        return (byte) (i + ((((i ^ other) & ((-i) | i)) >> 31) & other));
    }

    private static final int floorDiv(short $this$floorDiv, short other) {
        int i = $this$floorDiv / other;
        return (($this$floorDiv ^ other) >= 0 || i * other == $this$floorDiv) ? i : i - 1;
    }

    private static final short mod(short $this$mod, short other) {
        int i = $this$mod % other;
        return (short) (i + ((((i ^ other) & ((-i) | i)) >> 31) & other));
    }

    private static final int floorDiv(short $this$floorDiv, int other) {
        int i = $this$floorDiv / other;
        return (($this$floorDiv ^ other) >= 0 || i * other == $this$floorDiv) ? i : i - 1;
    }

    private static final int mod(short $this$mod, int other) {
        int i = $this$mod % other;
        return i + ((((i ^ other) & ((-i) | i)) >> 31) & other);
    }

    private static final long floorDiv(short $this$floorDiv, long other) {
        long j = $this$floorDiv;
        long j2 = j / other;
        return ((j ^ other) >= 0 || j2 * other == j) ? j2 : j2 - 1;
    }

    private static final long mod(short $this$mod, long other) {
        long j = $this$mod % other;
        return j + ((((j ^ other) & ((-j) | j)) >> 63) & other);
    }

    private static final int floorDiv(int $this$floorDiv, byte other) {
        int i = $this$floorDiv / other;
        return (($this$floorDiv ^ other) >= 0 || i * other == $this$floorDiv) ? i : i - 1;
    }

    private static final byte mod(int $this$mod, byte other) {
        int i = $this$mod % other;
        return (byte) (i + ((((i ^ other) & ((-i) | i)) >> 31) & other));
    }

    private static final int floorDiv(int $this$floorDiv, short other) {
        int i = $this$floorDiv / other;
        return (($this$floorDiv ^ other) >= 0 || i * other == $this$floorDiv) ? i : i - 1;
    }

    private static final short mod(int $this$mod, short other) {
        int i = $this$mod % other;
        return (short) (i + ((((i ^ other) & ((-i) | i)) >> 31) & other));
    }

    private static final int floorDiv(int $this$floorDiv, int other) {
        int q = $this$floorDiv / other;
        return (($this$floorDiv ^ other) >= 0 || q * other == $this$floorDiv) ? q : q - 1;
    }

    private static final int mod(int $this$mod, int other) {
        int r = $this$mod % other;
        return ((((r ^ other) & ((-r) | r)) >> 31) & other) + r;
    }

    private static final long floorDiv(int $this$floorDiv, long other) {
        long j = $this$floorDiv;
        long j2 = j / other;
        return ((j ^ other) >= 0 || j2 * other == j) ? j2 : j2 - 1;
    }

    private static final long mod(int $this$mod, long other) {
        long j = $this$mod % other;
        return j + ((((j ^ other) & ((-j) | j)) >> 63) & other);
    }

    private static final long floorDiv(long $this$floorDiv, byte other) {
        long j = other;
        long j2 = $this$floorDiv / j;
        return (($this$floorDiv ^ j) >= 0 || j * j2 == $this$floorDiv) ? j2 : j2 - 1;
    }

    private static final byte mod(long $this$mod, byte other) {
        long j;
        long j2 = $this$mod % other;
        return (byte) (j2 + (j & (((j2 ^ j) & ((-j2) | j2)) >> 63)));
    }

    private static final long floorDiv(long $this$floorDiv, short other) {
        long j = other;
        long j2 = $this$floorDiv / j;
        return (($this$floorDiv ^ j) >= 0 || j * j2 == $this$floorDiv) ? j2 : j2 - 1;
    }

    private static final short mod(long $this$mod, short other) {
        long j;
        long j2 = $this$mod % other;
        return (short) (j2 + (j & (((j2 ^ j) & ((-j2) | j2)) >> 63)));
    }

    private static final long floorDiv(long $this$floorDiv, int other) {
        long j = other;
        long j2 = $this$floorDiv / j;
        return (($this$floorDiv ^ j) >= 0 || j * j2 == $this$floorDiv) ? j2 : j2 - 1;
    }

    private static final int mod(long $this$mod, int other) {
        long j = other;
        long j2 = $this$mod % j;
        return (int) (j2 + (j & (((j2 ^ j) & ((-j2) | j2)) >> 63)));
    }

    private static final long floorDiv(long $this$floorDiv, long other) {
        long q = $this$floorDiv / other;
        return (($this$floorDiv ^ other) >= 0 || q * other == $this$floorDiv) ? q : q - 1;
    }

    private static final long mod(long $this$mod, long other) {
        long r = $this$mod % other;
        return ((((r ^ other) & ((-r) | r)) >> 63) & other) + r;
    }

    private static final float mod(float $this$mod, float other) {
        float r = $this$mod % other;
        if (!(r == 0.0f)) {
            if (!(Math.signum(r) == Math.signum(other))) {
                return r + other;
            }
        }
        return r;
    }

    private static final double mod(float $this$mod, double other) {
        double d = $this$mod % other;
        if (d == 0.0d) {
            return d;
        }
        return !(Math.signum(d) == Math.signum(other)) ? d + other : d;
    }

    private static final double mod(double $this$mod, float other) {
        double d = other;
        double d2 = $this$mod % d;
        if (d2 == 0.0d) {
            return d2;
        }
        return !(Math.signum(d2) == Math.signum(d)) ? d2 + d : d2;
    }

    private static final double mod(double $this$mod, double other) {
        double r = $this$mod % other;
        if (!(r == 0.0d)) {
            if (!(Math.signum(r) == Math.signum(other))) {
                return r + other;
            }
        }
        return r;
    }
}
