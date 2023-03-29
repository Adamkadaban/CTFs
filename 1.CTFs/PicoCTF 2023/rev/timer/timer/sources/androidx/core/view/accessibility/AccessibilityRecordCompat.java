package androidx.core.view.accessibility;

import android.os.Build;
import android.os.Parcelable;
import android.view.View;
import android.view.accessibility.AccessibilityRecord;
import java.util.List;
/* loaded from: classes.dex */
public class AccessibilityRecordCompat {
    private final AccessibilityRecord mRecord;

    @Deprecated
    public AccessibilityRecordCompat(Object record) {
        this.mRecord = (AccessibilityRecord) record;
    }

    @Deprecated
    public Object getImpl() {
        return this.mRecord;
    }

    @Deprecated
    public static AccessibilityRecordCompat obtain(AccessibilityRecordCompat record) {
        return new AccessibilityRecordCompat(AccessibilityRecord.obtain(record.mRecord));
    }

    @Deprecated
    public static AccessibilityRecordCompat obtain() {
        return new AccessibilityRecordCompat(AccessibilityRecord.obtain());
    }

    @Deprecated
    public void setSource(View source) {
        this.mRecord.setSource(source);
    }

    @Deprecated
    public void setSource(View root, int virtualDescendantId) {
        setSource(this.mRecord, root, virtualDescendantId);
    }

    public static void setSource(AccessibilityRecord record, View root, int virtualDescendantId) {
        if (Build.VERSION.SDK_INT >= 16) {
            record.setSource(root, virtualDescendantId);
        }
    }

    @Deprecated
    public AccessibilityNodeInfoCompat getSource() {
        return AccessibilityNodeInfoCompat.wrapNonNullInstance(this.mRecord.getSource());
    }

    @Deprecated
    public int getWindowId() {
        return this.mRecord.getWindowId();
    }

    @Deprecated
    public boolean isChecked() {
        return this.mRecord.isChecked();
    }

    @Deprecated
    public void setChecked(boolean isChecked) {
        this.mRecord.setChecked(isChecked);
    }

    @Deprecated
    public boolean isEnabled() {
        return this.mRecord.isEnabled();
    }

    @Deprecated
    public void setEnabled(boolean isEnabled) {
        this.mRecord.setEnabled(isEnabled);
    }

    @Deprecated
    public boolean isPassword() {
        return this.mRecord.isPassword();
    }

    @Deprecated
    public void setPassword(boolean isPassword) {
        this.mRecord.setPassword(isPassword);
    }

    @Deprecated
    public boolean isFullScreen() {
        return this.mRecord.isFullScreen();
    }

    @Deprecated
    public void setFullScreen(boolean isFullScreen) {
        this.mRecord.setFullScreen(isFullScreen);
    }

    @Deprecated
    public boolean isScrollable() {
        return this.mRecord.isScrollable();
    }

    @Deprecated
    public void setScrollable(boolean scrollable) {
        this.mRecord.setScrollable(scrollable);
    }

    @Deprecated
    public int getItemCount() {
        return this.mRecord.getItemCount();
    }

    @Deprecated
    public void setItemCount(int itemCount) {
        this.mRecord.setItemCount(itemCount);
    }

    @Deprecated
    public int getCurrentItemIndex() {
        return this.mRecord.getCurrentItemIndex();
    }

    @Deprecated
    public void setCurrentItemIndex(int currentItemIndex) {
        this.mRecord.setCurrentItemIndex(currentItemIndex);
    }

    @Deprecated
    public int getFromIndex() {
        return this.mRecord.getFromIndex();
    }

    @Deprecated
    public void setFromIndex(int fromIndex) {
        this.mRecord.setFromIndex(fromIndex);
    }

    @Deprecated
    public int getToIndex() {
        return this.mRecord.getToIndex();
    }

    @Deprecated
    public void setToIndex(int toIndex) {
        this.mRecord.setToIndex(toIndex);
    }

    @Deprecated
    public int getScrollX() {
        return this.mRecord.getScrollX();
    }

    @Deprecated
    public void setScrollX(int scrollX) {
        this.mRecord.setScrollX(scrollX);
    }

    @Deprecated
    public int getScrollY() {
        return this.mRecord.getScrollY();
    }

    @Deprecated
    public void setScrollY(int scrollY) {
        this.mRecord.setScrollY(scrollY);
    }

    @Deprecated
    public int getMaxScrollX() {
        return getMaxScrollX(this.mRecord);
    }

    public static int getMaxScrollX(AccessibilityRecord record) {
        if (Build.VERSION.SDK_INT >= 15) {
            return record.getMaxScrollX();
        }
        return 0;
    }

    @Deprecated
    public void setMaxScrollX(int maxScrollX) {
        setMaxScrollX(this.mRecord, maxScrollX);
    }

    public static void setMaxScrollX(AccessibilityRecord record, int maxScrollX) {
        if (Build.VERSION.SDK_INT >= 15) {
            record.setMaxScrollX(maxScrollX);
        }
    }

    @Deprecated
    public int getMaxScrollY() {
        return getMaxScrollY(this.mRecord);
    }

    public static int getMaxScrollY(AccessibilityRecord record) {
        if (Build.VERSION.SDK_INT >= 15) {
            return record.getMaxScrollY();
        }
        return 0;
    }

    @Deprecated
    public void setMaxScrollY(int maxScrollY) {
        setMaxScrollY(this.mRecord, maxScrollY);
    }

    public static void setMaxScrollY(AccessibilityRecord record, int maxScrollY) {
        if (Build.VERSION.SDK_INT >= 15) {
            record.setMaxScrollY(maxScrollY);
        }
    }

    @Deprecated
    public int getAddedCount() {
        return this.mRecord.getAddedCount();
    }

    @Deprecated
    public void setAddedCount(int addedCount) {
        this.mRecord.setAddedCount(addedCount);
    }

    @Deprecated
    public int getRemovedCount() {
        return this.mRecord.getRemovedCount();
    }

    @Deprecated
    public void setRemovedCount(int removedCount) {
        this.mRecord.setRemovedCount(removedCount);
    }

    @Deprecated
    public CharSequence getClassName() {
        return this.mRecord.getClassName();
    }

    @Deprecated
    public void setClassName(CharSequence className) {
        this.mRecord.setClassName(className);
    }

    @Deprecated
    public List<CharSequence> getText() {
        return this.mRecord.getText();
    }

    @Deprecated
    public CharSequence getBeforeText() {
        return this.mRecord.getBeforeText();
    }

    @Deprecated
    public void setBeforeText(CharSequence beforeText) {
        this.mRecord.setBeforeText(beforeText);
    }

    @Deprecated
    public CharSequence getContentDescription() {
        return this.mRecord.getContentDescription();
    }

    @Deprecated
    public void setContentDescription(CharSequence contentDescription) {
        this.mRecord.setContentDescription(contentDescription);
    }

    @Deprecated
    public Parcelable getParcelableData() {
        return this.mRecord.getParcelableData();
    }

    @Deprecated
    public void setParcelableData(Parcelable parcelableData) {
        this.mRecord.setParcelableData(parcelableData);
    }

    @Deprecated
    public void recycle() {
        this.mRecord.recycle();
    }

    @Deprecated
    public int hashCode() {
        AccessibilityRecord accessibilityRecord = this.mRecord;
        if (accessibilityRecord == null) {
            return 0;
        }
        return accessibilityRecord.hashCode();
    }

    @Deprecated
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof AccessibilityRecordCompat) {
            AccessibilityRecordCompat other = (AccessibilityRecordCompat) obj;
            AccessibilityRecord accessibilityRecord = this.mRecord;
            if (accessibilityRecord == null) {
                if (other.mRecord != null) {
                    return false;
                }
            } else if (!accessibilityRecord.equals(other.mRecord)) {
                return false;
            }
            return true;
        }
        return false;
    }
}
