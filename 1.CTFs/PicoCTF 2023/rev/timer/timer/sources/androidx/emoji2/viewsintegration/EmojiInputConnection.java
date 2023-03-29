package androidx.emoji2.viewsintegration;

import android.text.Editable;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputConnectionWrapper;
import android.widget.TextView;
import androidx.emoji2.text.EmojiCompat;
/* loaded from: classes.dex */
final class EmojiInputConnection extends InputConnectionWrapper {
    private final EmojiCompatDeleteHelper mEmojiCompatDeleteHelper;
    private final TextView mTextView;

    /* JADX INFO: Access modifiers changed from: package-private */
    public EmojiInputConnection(TextView textView, InputConnection inputConnection, EditorInfo outAttrs) {
        this(textView, inputConnection, outAttrs, new EmojiCompatDeleteHelper());
    }

    EmojiInputConnection(TextView textView, InputConnection inputConnection, EditorInfo outAttrs, EmojiCompatDeleteHelper emojiCompatDeleteHelper) {
        super(inputConnection, false);
        this.mTextView = textView;
        this.mEmojiCompatDeleteHelper = emojiCompatDeleteHelper;
        emojiCompatDeleteHelper.updateEditorInfoAttrs(outAttrs);
    }

    @Override // android.view.inputmethod.InputConnectionWrapper, android.view.inputmethod.InputConnection
    public boolean deleteSurroundingText(int beforeLength, int afterLength) {
        boolean result = this.mEmojiCompatDeleteHelper.handleDeleteSurroundingText(this, getEditable(), beforeLength, afterLength, false);
        return result || super.deleteSurroundingText(beforeLength, afterLength);
    }

    @Override // android.view.inputmethod.InputConnectionWrapper, android.view.inputmethod.InputConnection
    public boolean deleteSurroundingTextInCodePoints(int beforeLength, int afterLength) {
        boolean result = this.mEmojiCompatDeleteHelper.handleDeleteSurroundingText(this, getEditable(), beforeLength, afterLength, true);
        return result || super.deleteSurroundingTextInCodePoints(beforeLength, afterLength);
    }

    private Editable getEditable() {
        return this.mTextView.getEditableText();
    }

    /* loaded from: classes.dex */
    public static class EmojiCompatDeleteHelper {
        public boolean handleDeleteSurroundingText(InputConnection inputConnection, Editable editable, int beforeLength, int afterLength, boolean inCodePoints) {
            return EmojiCompat.handleDeleteSurroundingText(inputConnection, editable, beforeLength, afterLength, inCodePoints);
        }

        public void updateEditorInfoAttrs(EditorInfo outAttrs) {
            if (EmojiCompat.isConfigured()) {
                EmojiCompat.get().updateEditorInfo(outAttrs);
            }
        }
    }
}
