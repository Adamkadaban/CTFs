package com.google.android.material.datepicker;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.material.datepicker.CalendarConstraints;
import java.util.Arrays;
/* loaded from: classes.dex */
public class DateValidatorPointBackward implements CalendarConstraints.DateValidator {
    public static final Parcelable.Creator<DateValidatorPointBackward> CREATOR = new Parcelable.Creator<DateValidatorPointBackward>() { // from class: com.google.android.material.datepicker.DateValidatorPointBackward.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public DateValidatorPointBackward createFromParcel(Parcel source) {
            return new DateValidatorPointBackward(source.readLong());
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public DateValidatorPointBackward[] newArray(int size) {
            return new DateValidatorPointBackward[size];
        }
    };
    private final long point;

    private DateValidatorPointBackward(long point) {
        this.point = point;
    }

    public static DateValidatorPointBackward before(long point) {
        return new DateValidatorPointBackward(point);
    }

    public static DateValidatorPointBackward now() {
        return before(UtcDates.getTodayCalendar().getTimeInMillis());
    }

    @Override // com.google.android.material.datepicker.CalendarConstraints.DateValidator
    public boolean isValid(long date) {
        return date <= this.point;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeLong(this.point);
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof DateValidatorPointBackward) {
            DateValidatorPointBackward that = (DateValidatorPointBackward) o;
            return this.point == that.point;
        }
        return false;
    }

    public int hashCode() {
        Object[] hashedFields = {Long.valueOf(this.point)};
        return Arrays.hashCode(hashedFields);
    }
}
