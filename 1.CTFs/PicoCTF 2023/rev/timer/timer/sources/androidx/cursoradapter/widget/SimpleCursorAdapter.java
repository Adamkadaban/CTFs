package androidx.cursoradapter.widget;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
/* loaded from: classes.dex */
public class SimpleCursorAdapter extends ResourceCursorAdapter {
    private CursorToStringConverter mCursorToStringConverter;
    protected int[] mFrom;
    String[] mOriginalFrom;
    private int mStringConversionColumn;
    protected int[] mTo;
    private ViewBinder mViewBinder;

    /* loaded from: classes.dex */
    public interface CursorToStringConverter {
        CharSequence convertToString(Cursor cursor);
    }

    /* loaded from: classes.dex */
    public interface ViewBinder {
        boolean setViewValue(View view, Cursor cursor, int i);
    }

    @Deprecated
    public SimpleCursorAdapter(Context context, int layout, Cursor c, String[] from, int[] to) {
        super(context, layout, c);
        this.mStringConversionColumn = -1;
        this.mTo = to;
        this.mOriginalFrom = from;
        findColumns(c, from);
    }

    public SimpleCursorAdapter(Context context, int layout, Cursor c, String[] from, int[] to, int flags) {
        super(context, layout, c, flags);
        this.mStringConversionColumn = -1;
        this.mTo = to;
        this.mOriginalFrom = from;
        findColumns(c, from);
    }

    @Override // androidx.cursoradapter.widget.CursorAdapter
    public void bindView(View view, Context context, Cursor cursor) {
        ViewBinder binder = this.mViewBinder;
        int count = this.mTo.length;
        int[] from = this.mFrom;
        int[] to = this.mTo;
        for (int i = 0; i < count; i++) {
            View v = view.findViewById(to[i]);
            if (v != null) {
                boolean bound = false;
                if (binder != null) {
                    bound = binder.setViewValue(v, cursor, from[i]);
                }
                if (bound) {
                    continue;
                } else {
                    String text = cursor.getString(from[i]);
                    if (text == null) {
                        text = "";
                    }
                    if (v instanceof TextView) {
                        setViewText((TextView) v, text);
                    } else if (v instanceof ImageView) {
                        setViewImage((ImageView) v, text);
                    } else {
                        throw new IllegalStateException(v.getClass().getName() + " is not a  view that can be bounds by this SimpleCursorAdapter");
                    }
                }
            }
        }
    }

    public ViewBinder getViewBinder() {
        return this.mViewBinder;
    }

    public void setViewBinder(ViewBinder viewBinder) {
        this.mViewBinder = viewBinder;
    }

    public void setViewImage(ImageView v, String value) {
        try {
            v.setImageResource(Integer.parseInt(value));
        } catch (NumberFormatException e) {
            v.setImageURI(Uri.parse(value));
        }
    }

    public void setViewText(TextView v, String text) {
        v.setText(text);
    }

    public int getStringConversionColumn() {
        return this.mStringConversionColumn;
    }

    public void setStringConversionColumn(int stringConversionColumn) {
        this.mStringConversionColumn = stringConversionColumn;
    }

    public CursorToStringConverter getCursorToStringConverter() {
        return this.mCursorToStringConverter;
    }

    public void setCursorToStringConverter(CursorToStringConverter cursorToStringConverter) {
        this.mCursorToStringConverter = cursorToStringConverter;
    }

    @Override // androidx.cursoradapter.widget.CursorAdapter, androidx.cursoradapter.widget.CursorFilter.CursorFilterClient
    public CharSequence convertToString(Cursor cursor) {
        CursorToStringConverter cursorToStringConverter = this.mCursorToStringConverter;
        if (cursorToStringConverter != null) {
            return cursorToStringConverter.convertToString(cursor);
        }
        int i = this.mStringConversionColumn;
        if (i > -1) {
            return cursor.getString(i);
        }
        return super.convertToString(cursor);
    }

    private void findColumns(Cursor c, String[] from) {
        if (c != null) {
            int count = from.length;
            int[] iArr = this.mFrom;
            if (iArr == null || iArr.length != count) {
                this.mFrom = new int[count];
            }
            for (int i = 0; i < count; i++) {
                this.mFrom[i] = c.getColumnIndexOrThrow(from[i]);
            }
            return;
        }
        this.mFrom = null;
    }

    @Override // androidx.cursoradapter.widget.CursorAdapter
    public Cursor swapCursor(Cursor c) {
        findColumns(c, this.mOriginalFrom);
        return super.swapCursor(c);
    }

    public void changeCursorAndColumns(Cursor c, String[] from, int[] to) {
        this.mOriginalFrom = from;
        this.mTo = to;
        findColumns(c, from);
        super.changeCursor(c);
    }
}
