package androidx.core.view.inputmethod;

import android.os.Build;
import android.os.Bundle;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.view.inputmethod.EditorInfo;
import androidx.core.util.Preconditions;
/* loaded from: classes.dex */
public final class EditorInfoCompat {
    private static final String CONTENT_MIME_TYPES_INTEROP_KEY = "android.support.v13.view.inputmethod.EditorInfoCompat.CONTENT_MIME_TYPES";
    private static final String CONTENT_MIME_TYPES_KEY = "androidx.core.view.inputmethod.EditorInfoCompat.CONTENT_MIME_TYPES";
    private static final String CONTENT_SELECTION_END_KEY = "androidx.core.view.inputmethod.EditorInfoCompat.CONTENT_SELECTION_END";
    private static final String CONTENT_SELECTION_HEAD_KEY = "androidx.core.view.inputmethod.EditorInfoCompat.CONTENT_SELECTION_HEAD";
    private static final String CONTENT_SURROUNDING_TEXT_KEY = "androidx.core.view.inputmethod.EditorInfoCompat.CONTENT_SURROUNDING_TEXT";
    private static final String[] EMPTY_STRING_ARRAY = new String[0];
    public static final int IME_FLAG_FORCE_ASCII = Integer.MIN_VALUE;
    public static final int IME_FLAG_NO_PERSONALIZED_LEARNING = 16777216;
    static final int MAX_INITIAL_SELECTION_LENGTH = 1024;
    static final int MEMORY_EFFICIENT_TEXT_LENGTH = 2048;

    public static void setContentMimeTypes(EditorInfo editorInfo, String[] contentMimeTypes) {
        if (Build.VERSION.SDK_INT >= 25) {
            editorInfo.contentMimeTypes = contentMimeTypes;
            return;
        }
        if (editorInfo.extras == null) {
            editorInfo.extras = new Bundle();
        }
        editorInfo.extras.putStringArray(CONTENT_MIME_TYPES_KEY, contentMimeTypes);
        editorInfo.extras.putStringArray(CONTENT_MIME_TYPES_INTEROP_KEY, contentMimeTypes);
    }

    public static String[] getContentMimeTypes(EditorInfo editorInfo) {
        if (Build.VERSION.SDK_INT >= 25) {
            String[] result = editorInfo.contentMimeTypes;
            return result != null ? result : EMPTY_STRING_ARRAY;
        } else if (editorInfo.extras == null) {
            return EMPTY_STRING_ARRAY;
        } else {
            String[] result2 = editorInfo.extras.getStringArray(CONTENT_MIME_TYPES_KEY);
            if (result2 == null) {
                result2 = editorInfo.extras.getStringArray(CONTENT_MIME_TYPES_INTEROP_KEY);
            }
            return result2 != null ? result2 : EMPTY_STRING_ARRAY;
        }
    }

    public static void setInitialSurroundingText(EditorInfo editorInfo, CharSequence sourceText) {
        if (Build.VERSION.SDK_INT >= 30) {
            Api30Impl.setInitialSurroundingSubText(editorInfo, sourceText, 0);
        } else {
            setInitialSurroundingSubText(editorInfo, sourceText, 0);
        }
    }

    public static void setInitialSurroundingSubText(EditorInfo editorInfo, CharSequence subText, int subTextStart) {
        int subTextSelStart;
        int subTextSelEnd;
        Preconditions.checkNotNull(subText);
        if (Build.VERSION.SDK_INT >= 30) {
            Api30Impl.setInitialSurroundingSubText(editorInfo, subText, subTextStart);
            return;
        }
        if (editorInfo.initialSelStart > editorInfo.initialSelEnd) {
            subTextSelStart = editorInfo.initialSelEnd - subTextStart;
        } else {
            subTextSelStart = editorInfo.initialSelStart - subTextStart;
        }
        if (editorInfo.initialSelStart > editorInfo.initialSelEnd) {
            subTextSelEnd = editorInfo.initialSelStart - subTextStart;
        } else {
            subTextSelEnd = editorInfo.initialSelEnd - subTextStart;
        }
        int subTextLength = subText.length();
        if (subTextStart < 0 || subTextSelStart < 0 || subTextSelEnd > subTextLength) {
            setSurroundingText(editorInfo, null, 0, 0);
        } else if (isPasswordInputType(editorInfo.inputType)) {
            setSurroundingText(editorInfo, null, 0, 0);
        } else if (subTextLength <= 2048) {
            setSurroundingText(editorInfo, subText, subTextSelStart, subTextSelEnd);
        } else {
            trimLongSurroundingText(editorInfo, subText, subTextSelStart, subTextSelEnd);
        }
    }

    private static void trimLongSurroundingText(EditorInfo editorInfo, CharSequence subText, int selStart, int selEnd) {
        CharSequence newInitialSurroundingText;
        int sourceSelLength = selEnd - selStart;
        int newSelLength = sourceSelLength > 1024 ? 0 : sourceSelLength;
        int subTextAfterCursorLength = subText.length() - selEnd;
        int maxLengthMinusSelection = 2048 - newSelLength;
        int possibleMaxBeforeCursorLength = Math.min(selStart, (int) (maxLengthMinusSelection * 0.8d));
        int newAfterCursorLength = Math.min(subTextAfterCursorLength, maxLengthMinusSelection - possibleMaxBeforeCursorLength);
        int newBeforeCursorLength = Math.min(selStart, maxLengthMinusSelection - newAfterCursorLength);
        int newBeforeCursorHead = selStart - newBeforeCursorLength;
        if (isCutOnSurrogate(subText, selStart - newBeforeCursorLength, 0)) {
            newBeforeCursorHead++;
            newBeforeCursorLength--;
        }
        if (isCutOnSurrogate(subText, (selEnd + newAfterCursorLength) - 1, 1)) {
            newAfterCursorLength--;
        }
        int newTextLength = newBeforeCursorLength + newSelLength + newAfterCursorLength;
        if (newSelLength != sourceSelLength) {
            CharSequence beforeCursor = subText.subSequence(newBeforeCursorHead, newBeforeCursorHead + newBeforeCursorLength);
            CharSequence afterCursor = subText.subSequence(selEnd, selEnd + newAfterCursorLength);
            newInitialSurroundingText = TextUtils.concat(beforeCursor, afterCursor);
        } else {
            newInitialSurroundingText = subText.subSequence(newBeforeCursorHead, newBeforeCursorHead + newTextLength);
        }
        int newSelHead = 0 + newBeforeCursorLength;
        setSurroundingText(editorInfo, newInitialSurroundingText, newSelHead, newSelHead + newSelLength);
    }

    public static CharSequence getInitialTextBeforeCursor(EditorInfo editorInfo, int length, int flags) {
        CharSequence surroundingText;
        if (Build.VERSION.SDK_INT >= 30) {
            return Api30Impl.getInitialTextBeforeCursor(editorInfo, length, flags);
        }
        if (editorInfo.extras == null || (surroundingText = editorInfo.extras.getCharSequence(CONTENT_SURROUNDING_TEXT_KEY)) == null) {
            return null;
        }
        int selectionHead = editorInfo.extras.getInt(CONTENT_SELECTION_HEAD_KEY);
        int textLength = Math.min(length, selectionHead);
        if ((flags & 1) != 0) {
            return surroundingText.subSequence(selectionHead - textLength, selectionHead);
        }
        return TextUtils.substring(surroundingText, selectionHead - textLength, selectionHead);
    }

    public static CharSequence getInitialSelectedText(EditorInfo editorInfo, int flags) {
        CharSequence surroundingText;
        if (Build.VERSION.SDK_INT >= 30) {
            return Api30Impl.getInitialSelectedText(editorInfo, flags);
        }
        if (editorInfo.extras == null) {
            return null;
        }
        int correctedTextSelStart = Math.min(editorInfo.initialSelStart, editorInfo.initialSelEnd);
        int correctedTextSelEnd = Math.max(editorInfo.initialSelStart, editorInfo.initialSelEnd);
        int selectionHead = editorInfo.extras.getInt(CONTENT_SELECTION_HEAD_KEY);
        int selectionEnd = editorInfo.extras.getInt(CONTENT_SELECTION_END_KEY);
        int sourceSelLength = correctedTextSelEnd - correctedTextSelStart;
        if (editorInfo.initialSelStart < 0 || editorInfo.initialSelEnd < 0 || selectionEnd - selectionHead != sourceSelLength || (surroundingText = editorInfo.extras.getCharSequence(CONTENT_SURROUNDING_TEXT_KEY)) == null) {
            return null;
        }
        if ((flags & 1) != 0) {
            return surroundingText.subSequence(selectionHead, selectionEnd);
        }
        return TextUtils.substring(surroundingText, selectionHead, selectionEnd);
    }

    public static CharSequence getInitialTextAfterCursor(EditorInfo editorInfo, int length, int flags) {
        CharSequence surroundingText;
        if (Build.VERSION.SDK_INT >= 30) {
            return Api30Impl.getInitialTextAfterCursor(editorInfo, length, flags);
        }
        if (editorInfo.extras == null || (surroundingText = editorInfo.extras.getCharSequence(CONTENT_SURROUNDING_TEXT_KEY)) == null) {
            return null;
        }
        int selectionEnd = editorInfo.extras.getInt(CONTENT_SELECTION_END_KEY);
        int textLength = Math.min(length, surroundingText.length() - selectionEnd);
        if ((flags & 1) != 0) {
            return surroundingText.subSequence(selectionEnd, selectionEnd + textLength);
        }
        return TextUtils.substring(surroundingText, selectionEnd, selectionEnd + textLength);
    }

    private static boolean isCutOnSurrogate(CharSequence sourceText, int cutPosition, int policy) {
        switch (policy) {
            case 0:
                return Character.isLowSurrogate(sourceText.charAt(cutPosition));
            case 1:
                return Character.isHighSurrogate(sourceText.charAt(cutPosition));
            default:
                return false;
        }
    }

    private static boolean isPasswordInputType(int inputType) {
        int variation = inputType & 4095;
        return variation == 129 || variation == 225 || variation == 18;
    }

    private static void setSurroundingText(EditorInfo editorInfo, CharSequence surroundingText, int selectionHead, int selectionEnd) {
        if (editorInfo.extras == null) {
            editorInfo.extras = new Bundle();
        }
        CharSequence surroundingTextCopy = surroundingText != null ? new SpannableStringBuilder(surroundingText) : null;
        editorInfo.extras.putCharSequence(CONTENT_SURROUNDING_TEXT_KEY, surroundingTextCopy);
        editorInfo.extras.putInt(CONTENT_SELECTION_HEAD_KEY, selectionHead);
        editorInfo.extras.putInt(CONTENT_SELECTION_END_KEY, selectionEnd);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getProtocol(EditorInfo editorInfo) {
        if (Build.VERSION.SDK_INT >= 25) {
            return 1;
        }
        if (editorInfo.extras == null) {
            return 0;
        }
        boolean hasNewKey = editorInfo.extras.containsKey(CONTENT_MIME_TYPES_KEY);
        boolean hasOldKey = editorInfo.extras.containsKey(CONTENT_MIME_TYPES_INTEROP_KEY);
        if (hasNewKey && hasOldKey) {
            return 4;
        }
        if (hasNewKey) {
            return 3;
        }
        return hasOldKey ? 2 : 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class Api30Impl {
        private Api30Impl() {
        }

        static void setInitialSurroundingSubText(EditorInfo editorInfo, CharSequence sourceText, int subTextStart) {
            editorInfo.setInitialSurroundingSubText(sourceText, subTextStart);
        }

        static CharSequence getInitialTextBeforeCursor(EditorInfo editorInfo, int length, int flags) {
            return editorInfo.getInitialTextBeforeCursor(length, flags);
        }

        static CharSequence getInitialSelectedText(EditorInfo editorInfo, int flags) {
            return editorInfo.getInitialSelectedText(flags);
        }

        static CharSequence getInitialTextAfterCursor(EditorInfo editorInfo, int length, int flags) {
            return editorInfo.getInitialTextAfterCursor(length, flags);
        }
    }
}
