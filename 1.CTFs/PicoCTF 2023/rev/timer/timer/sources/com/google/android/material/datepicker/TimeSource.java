package com.google.android.material.datepicker;

import java.util.Calendar;
import java.util.TimeZone;
/* loaded from: classes.dex */
class TimeSource {
    private static final TimeSource SYSTEM_TIME_SOURCE = new TimeSource(null, null);
    private final Long fixedTimeMs;
    private final TimeZone fixedTimeZone;

    private TimeSource(Long fixedTimeMs, TimeZone fixedTimeZone) {
        this.fixedTimeMs = fixedTimeMs;
        this.fixedTimeZone = fixedTimeZone;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TimeSource system() {
        return SYSTEM_TIME_SOURCE;
    }

    static TimeSource fixed(long epochMs, TimeZone timeZone) {
        return new TimeSource(Long.valueOf(epochMs), timeZone);
    }

    static TimeSource fixed(long epochMs) {
        return new TimeSource(Long.valueOf(epochMs), null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Calendar now() {
        return now(this.fixedTimeZone);
    }

    Calendar now(TimeZone timeZone) {
        Calendar calendar = timeZone == null ? Calendar.getInstance() : Calendar.getInstance(timeZone);
        Long l = this.fixedTimeMs;
        if (l != null) {
            calendar.setTimeInMillis(l.longValue());
        }
        return calendar;
    }
}
