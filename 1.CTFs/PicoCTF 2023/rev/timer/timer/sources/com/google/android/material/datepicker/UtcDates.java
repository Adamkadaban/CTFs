package com.google.android.material.datepicker;

import android.content.res.Resources;
import android.icu.text.DateFormat;
import com.google.android.material.R;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicReference;
/* loaded from: classes.dex */
class UtcDates {
    static final String UTC = "UTC";
    static AtomicReference<TimeSource> timeSourceRef = new AtomicReference<>();

    static void setTimeSource(TimeSource timeSource) {
        timeSourceRef.set(timeSource);
    }

    static TimeSource getTimeSource() {
        TimeSource timeSource = timeSourceRef.get();
        return timeSource == null ? TimeSource.system() : timeSource;
    }

    private UtcDates() {
    }

    private static TimeZone getTimeZone() {
        return TimeZone.getTimeZone(UTC);
    }

    private static android.icu.util.TimeZone getUtcAndroidTimeZone() {
        return android.icu.util.TimeZone.getTimeZone(UTC);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Calendar getTodayCalendar() {
        Calendar today = getTimeSource().now();
        today.set(11, 0);
        today.set(12, 0);
        today.set(13, 0);
        today.set(14, 0);
        today.setTimeZone(getTimeZone());
        return today;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Calendar getUtcCalendar() {
        return getUtcCalendarOf(null);
    }

    static Calendar getUtcCalendarOf(Calendar rawCalendar) {
        Calendar utc = Calendar.getInstance(getTimeZone());
        if (rawCalendar == null) {
            utc.clear();
        } else {
            utc.setTimeInMillis(rawCalendar.getTimeInMillis());
        }
        return utc;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Calendar getDayCopy(Calendar rawCalendar) {
        Calendar rawCalendarInUtc = getUtcCalendarOf(rawCalendar);
        Calendar utcCalendar = getUtcCalendar();
        utcCalendar.set(rawCalendarInUtc.get(1), rawCalendarInUtc.get(2), rawCalendarInUtc.get(5));
        return utcCalendar;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static long canonicalYearMonthDay(long rawDate) {
        Calendar rawCalendar = getUtcCalendar();
        rawCalendar.setTimeInMillis(rawDate);
        Calendar sanitizedStartItem = getDayCopy(rawCalendar);
        return sanitizedStartItem.getTimeInMillis();
    }

    private static DateFormat getAndroidFormat(String pattern, Locale locale) {
        DateFormat format = DateFormat.getInstanceForSkeleton(pattern, locale);
        format.setTimeZone(getUtcAndroidTimeZone());
        return format;
    }

    private static java.text.DateFormat getFormat(int style, Locale locale) {
        java.text.DateFormat format = java.text.DateFormat.getDateInstance(style, locale);
        format.setTimeZone(getTimeZone());
        return format;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SimpleDateFormat getTextInputFormat() {
        String pattern = ((SimpleDateFormat) java.text.DateFormat.getDateInstance(3, Locale.getDefault())).toPattern().replaceAll("\\s+", "");
        SimpleDateFormat format = new SimpleDateFormat(pattern, Locale.getDefault());
        format.setTimeZone(getTimeZone());
        format.setLenient(false);
        return format;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String getTextInputHint(Resources res, SimpleDateFormat format) {
        String formatHint = format.toPattern();
        String yearChar = res.getString(R.string.mtrl_picker_text_input_year_abbr);
        String monthChar = res.getString(R.string.mtrl_picker_text_input_month_abbr);
        String dayChar = res.getString(R.string.mtrl_picker_text_input_day_abbr);
        if (formatHint.replaceAll("[^y]", "").length() == 1) {
            formatHint = formatHint.replace("y", "yyyy");
        }
        return formatHint.replace("d", dayChar).replace("M", monthChar).replace("y", yearChar);
    }

    static SimpleDateFormat getSimpleFormat(String pattern) {
        return getSimpleFormat(pattern, Locale.getDefault());
    }

    private static SimpleDateFormat getSimpleFormat(String pattern, Locale locale) {
        SimpleDateFormat format = new SimpleDateFormat(pattern, locale);
        format.setTimeZone(getTimeZone());
        return format;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static DateFormat getYearAbbrMonthDayFormat(Locale locale) {
        return getAndroidFormat("yMMMd", locale);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static DateFormat getAbbrMonthDayFormat(Locale locale) {
        return getAndroidFormat("MMMd", locale);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static DateFormat getAbbrMonthWeekdayDayFormat(Locale locale) {
        return getAndroidFormat("MMMEd", locale);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static DateFormat getYearAbbrMonthWeekdayDayFormat(Locale locale) {
        return getAndroidFormat("yMMMEd", locale);
    }

    static java.text.DateFormat getMediumFormat() {
        return getMediumFormat(Locale.getDefault());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static java.text.DateFormat getMediumFormat(Locale locale) {
        return getFormat(2, locale);
    }

    static java.text.DateFormat getMediumNoYear() {
        return getMediumNoYear(Locale.getDefault());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static java.text.DateFormat getMediumNoYear(Locale locale) {
        SimpleDateFormat format = (SimpleDateFormat) getMediumFormat(locale);
        format.applyPattern(removeYearFromDateFormatPattern(format.toPattern()));
        return format;
    }

    static java.text.DateFormat getFullFormat() {
        return getFullFormat(Locale.getDefault());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static java.text.DateFormat getFullFormat(Locale locale) {
        return getFormat(0, locale);
    }

    private static String removeYearFromDateFormatPattern(String pattern) {
        int yearPosition = findCharactersInDateFormatPattern(pattern, "yY", 1, 0);
        if (yearPosition >= pattern.length()) {
            return pattern;
        }
        String monthDayCharacters = "EMd";
        int yearEndPosition = findCharactersInDateFormatPattern(pattern, "EMd", 1, yearPosition);
        if (yearEndPosition < pattern.length()) {
            monthDayCharacters = "EMd,";
        }
        int yearStartPosition = findCharactersInDateFormatPattern(pattern, monthDayCharacters, -1, yearPosition);
        String yearPattern = pattern.substring(yearStartPosition + 1, yearEndPosition);
        return pattern.replace(yearPattern, " ").trim();
    }

    private static int findCharactersInDateFormatPattern(String pattern, String characterSequence, int increment, int initialPosition) {
        int position = initialPosition;
        while (position >= 0 && position < pattern.length() && characterSequence.indexOf(pattern.charAt(position)) == -1) {
            if (pattern.charAt(position) == '\'') {
                position += increment;
                while (position >= 0 && position < pattern.length() && pattern.charAt(position) != '\'') {
                    position += increment;
                }
            }
            position += increment;
        }
        return position;
    }
}
