package com.google.android.material.datepicker;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.Arrays;
import java.util.Calendar;
import java.util.GregorianCalendar;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public final class Month implements Comparable<Month>, Parcelable {
    public static final Parcelable.Creator<Month> CREATOR = new Parcelable.Creator<Month>() { // from class: com.google.android.material.datepicker.Month.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public Month createFromParcel(Parcel source) {
            int year = source.readInt();
            int month = source.readInt();
            return Month.create(year, month);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public Month[] newArray(int size) {
            return new Month[size];
        }
    };
    final int daysInMonth;
    final int daysInWeek;
    private final Calendar firstOfMonth;
    private String longName;
    final int month;
    final long timeInMillis;
    final int year;

    private Month(Calendar rawCalendar) {
        rawCalendar.set(5, 1);
        Calendar dayCopy = UtcDates.getDayCopy(rawCalendar);
        this.firstOfMonth = dayCopy;
        this.month = dayCopy.get(2);
        this.year = dayCopy.get(1);
        this.daysInWeek = dayCopy.getMaximum(7);
        this.daysInMonth = dayCopy.getActualMaximum(5);
        this.timeInMillis = dayCopy.getTimeInMillis();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Month create(long timeInMillis) {
        Calendar calendar = UtcDates.getUtcCalendar();
        calendar.setTimeInMillis(timeInMillis);
        return new Month(calendar);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Month create(int year, int month) {
        Calendar calendar = UtcDates.getUtcCalendar();
        calendar.set(1, year);
        calendar.set(2, month);
        return new Month(calendar);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Month current() {
        return new Month(UtcDates.getTodayCalendar());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int daysFromStartOfWeekToFirstOfMonth() {
        int difference = this.firstOfMonth.get(7) - this.firstOfMonth.getFirstDayOfWeek();
        if (difference < 0) {
            return difference + this.daysInWeek;
        }
        return difference;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof Month) {
            Month that = (Month) o;
            return this.month == that.month && this.year == that.year;
        }
        return false;
    }

    public int hashCode() {
        Object[] hashedFields = {Integer.valueOf(this.month), Integer.valueOf(this.year)};
        return Arrays.hashCode(hashedFields);
    }

    @Override // java.lang.Comparable
    public int compareTo(Month other) {
        return this.firstOfMonth.compareTo(other.firstOfMonth);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int monthsUntil(Month other) {
        if (this.firstOfMonth instanceof GregorianCalendar) {
            return ((other.year - this.year) * 12) + (other.month - this.month);
        }
        throw new IllegalArgumentException("Only Gregorian calendars are supported.");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public long getStableId() {
        return this.firstOfMonth.getTimeInMillis();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public long getDay(int day) {
        Calendar dayCalendar = UtcDates.getDayCopy(this.firstOfMonth);
        dayCalendar.set(5, day);
        return dayCalendar.getTimeInMillis();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getDayOfMonth(long date) {
        Calendar dayCalendar = UtcDates.getDayCopy(this.firstOfMonth);
        dayCalendar.setTimeInMillis(date);
        return dayCalendar.get(5);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Month monthsLater(int months) {
        Calendar laterMonth = UtcDates.getDayCopy(this.firstOfMonth);
        laterMonth.add(2, months);
        return new Month(laterMonth);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String getLongName() {
        if (this.longName == null) {
            this.longName = DateStrings.getYearMonth(this.firstOfMonth.getTimeInMillis());
        }
        return this.longName;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(this.year);
        dest.writeInt(this.month);
    }
}
