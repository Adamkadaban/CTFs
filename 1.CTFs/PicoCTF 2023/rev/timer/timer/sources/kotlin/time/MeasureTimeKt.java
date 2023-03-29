package kotlin.time;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.time.TimeSource;
/* compiled from: measureTime.kt */
@Metadata(d1 = {"\u0000\"\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a/\u0010\u0000\u001a\u00020\u00012\f\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u0003H\u0087\bø\u0001\u0000ø\u0001\u0001\u0082\u0002\n\n\b\b\u0001\u0012\u0002\u0010\u0001 \u0001¢\u0006\u0002\u0010\u0005\u001a3\u0010\u0006\u001a\b\u0012\u0004\u0012\u0002H\b0\u0007\"\u0004\b\u0000\u0010\b2\f\u0010\u0002\u001a\b\u0012\u0004\u0012\u0002H\b0\u0003H\u0087\bø\u0001\u0001\u0082\u0002\n\n\b\b\u0001\u0012\u0002\u0010\u0001 \u0001\u001a3\u0010\u0000\u001a\u00020\u0001*\u00020\t2\f\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u0003H\u0087\bø\u0001\u0000ø\u0001\u0001\u0082\u0002\n\n\b\b\u0001\u0012\u0002\u0010\u0001 \u0001¢\u0006\u0002\u0010\n\u001a7\u0010\u0006\u001a\b\u0012\u0004\u0012\u0002H\b0\u0007\"\u0004\b\u0000\u0010\b*\u00020\t2\f\u0010\u0002\u001a\b\u0012\u0004\u0012\u0002H\b0\u0003H\u0087\bø\u0001\u0001\u0082\u0002\n\n\b\b\u0001\u0012\u0002\u0010\u0001 \u0001\u0082\u0002\u000b\n\u0002\b\u0019\n\u0005\b\u009920\u0001¨\u0006\u000b"}, d2 = {"measureTime", "Lkotlin/time/Duration;", "block", "Lkotlin/Function0;", "", "(Lkotlin/jvm/functions/Function0;)J", "measureTimedValue", "Lkotlin/time/TimedValue;", "T", "Lkotlin/time/TimeSource;", "(Lkotlin/time/TimeSource;Lkotlin/jvm/functions/Function0;)J", "kotlin-stdlib"}, k = 2, mv = {1, 6, 0}, xi = 48)
/* loaded from: classes.dex */
public final class MeasureTimeKt {
    public static final long measureTime(Function0<Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        TimeSource $this$measureTime$iv = TimeSource.Monotonic.INSTANCE;
        TimeMark mark$iv = $this$measureTime$iv.markNow();
        block.invoke();
        return mark$iv.mo1312elapsedNowUwyO8pc();
    }

    public static final long measureTime(TimeSource $this$measureTime, Function0<Unit> block) {
        Intrinsics.checkNotNullParameter($this$measureTime, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        TimeMark mark = $this$measureTime.markNow();
        block.invoke();
        return mark.mo1312elapsedNowUwyO8pc();
    }

    public static final <T> TimedValue<T> measureTimedValue(Function0<? extends T> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        TimeSource $this$measureTimedValue$iv = TimeSource.Monotonic.INSTANCE;
        TimeMark mark$iv = $this$measureTimedValue$iv.markNow();
        Object result$iv = block.invoke();
        return new TimedValue<>(result$iv, mark$iv.mo1312elapsedNowUwyO8pc(), null);
    }

    public static final <T> TimedValue<T> measureTimedValue(TimeSource $this$measureTimedValue, Function0<? extends T> block) {
        Intrinsics.checkNotNullParameter($this$measureTimedValue, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        TimeMark mark = $this$measureTimedValue.markNow();
        Object result = block.invoke();
        return new TimedValue<>(result, mark.mo1312elapsedNowUwyO8pc(), null);
    }
}
