package kotlin.text;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: Char.kt */
@Metadata(d1 = {"\u0000\u001e\n\u0000\n\u0002\u0010\f\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0002\u001a\f\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0007\u001a\u0014\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0002H\u0007\u001a\f\u0010\u0004\u001a\u00020\u0002*\u00020\u0001H\u0007\u001a\u0014\u0010\u0004\u001a\u00020\u0002*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0002H\u0007\u001a\u0013\u0010\u0005\u001a\u0004\u0018\u00010\u0002*\u00020\u0001H\u0007¢\u0006\u0002\u0010\u0006\u001a\u001b\u0010\u0005\u001a\u0004\u0018\u00010\u0002*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0002H\u0007¢\u0006\u0002\u0010\u0007\u001a\u001c\u0010\b\u001a\u00020\t*\u00020\u00012\u0006\u0010\n\u001a\u00020\u00012\b\b\u0002\u0010\u000b\u001a\u00020\t\u001a\n\u0010\f\u001a\u00020\t*\u00020\u0001\u001a\u0015\u0010\r\u001a\u00020\u000e*\u00020\u00012\u0006\u0010\n\u001a\u00020\u000eH\u0087\n\u001a\f\u0010\u000f\u001a\u00020\u000e*\u00020\u0001H\u0007¨\u0006\u0010"}, d2 = {"digitToChar", "", "", "radix", "digitToInt", "digitToIntOrNull", "(C)Ljava/lang/Integer;", "(CI)Ljava/lang/Integer;", "equals", "", "other", "ignoreCase", "isSurrogate", "plus", "", "titlecase", "kotlin-stdlib"}, k = 5, mv = {1, 6, 0}, xi = 49, xs = "kotlin/text/CharsKt")
/* loaded from: classes.dex */
class CharsKt__CharKt extends CharsKt__CharJVMKt {
    public static final int digitToInt(char $this$digitToInt) {
        int it = CharsKt.digitOf($this$digitToInt, 10);
        if (it >= 0) {
            return it;
        }
        throw new IllegalArgumentException("Char " + $this$digitToInt + " is not a decimal digit");
    }

    public static final int digitToInt(char $this$digitToInt, int radix) {
        Integer digitToIntOrNull = CharsKt.digitToIntOrNull($this$digitToInt, radix);
        if (digitToIntOrNull != null) {
            return digitToIntOrNull.intValue();
        }
        throw new IllegalArgumentException("Char " + $this$digitToInt + " is not a digit in the given radix=" + radix);
    }

    public static final Integer digitToIntOrNull(char $this$digitToIntOrNull) {
        Integer valueOf = Integer.valueOf(CharsKt.digitOf($this$digitToIntOrNull, 10));
        int it = valueOf.intValue();
        if (it >= 0) {
            return valueOf;
        }
        return null;
    }

    public static final Integer digitToIntOrNull(char $this$digitToIntOrNull, int radix) {
        CharsKt.checkRadix(radix);
        Integer valueOf = Integer.valueOf(CharsKt.digitOf($this$digitToIntOrNull, radix));
        int it = valueOf.intValue();
        if (it >= 0) {
            return valueOf;
        }
        return null;
    }

    public static final char digitToChar(int $this$digitToChar) {
        boolean z = false;
        if ($this$digitToChar >= 0 && $this$digitToChar < 10) {
            z = true;
        }
        if (z) {
            return (char) ($this$digitToChar + 48);
        }
        throw new IllegalArgumentException("Int " + $this$digitToChar + " is not a decimal digit");
    }

    public static final char digitToChar(int $this$digitToChar, int radix) {
        boolean z = false;
        if (2 <= radix && radix < 37) {
            z = true;
        }
        if (!z) {
            throw new IllegalArgumentException("Invalid radix: " + radix + ". Valid radix values are in range 2..36");
        } else if ($this$digitToChar < 0 || $this$digitToChar >= radix) {
            throw new IllegalArgumentException("Digit " + $this$digitToChar + " does not represent a valid digit in radix " + radix);
        } else if ($this$digitToChar >= 10) {
            return (char) (((char) ($this$digitToChar + 65)) - '\n');
        } else {
            return (char) ($this$digitToChar + 48);
        }
    }

    public static final String titlecase(char $this$titlecase) {
        return _OneToManyTitlecaseMappingsKt.titlecaseImpl($this$titlecase);
    }

    private static final String plus(char $this$plus, String other) {
        Intrinsics.checkNotNullParameter(other, "other");
        return $this$plus + other;
    }

    public static /* synthetic */ boolean equals$default(char c, char c2, boolean z, int i, Object obj) {
        if ((i & 2) != 0) {
            z = false;
        }
        return CharsKt.equals(c, c2, z);
    }

    public static final boolean equals(char $this$equals, char other, boolean ignoreCase) {
        if ($this$equals == other) {
            return true;
        }
        if (!ignoreCase) {
            return false;
        }
        char thisUpper = Character.toUpperCase($this$equals);
        char otherUpper = Character.toUpperCase(other);
        return thisUpper == otherUpper || Character.toLowerCase(thisUpper) == Character.toLowerCase(otherUpper);
    }

    public static final boolean isSurrogate(char $this$isSurrogate) {
        return 55296 <= $this$isSurrogate && $this$isSurrogate < 57344;
    }
}
