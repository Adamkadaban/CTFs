package androidx.emoji2.viewsintegration;

import android.text.Editable;
import android.text.Selection;
import android.text.Spannable;
import android.text.TextWatcher;
import android.widget.EditText;
import androidx.emoji2.text.EmojiCompat;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
/* loaded from: classes.dex */
final class EmojiTextWatcher implements TextWatcher {
    private final EditText mEditText;
    private final boolean mExpectInitializedEmojiCompat;
    private EmojiCompat.InitCallback mInitCallback;
    private int mMaxEmojiCount = Integer.MAX_VALUE;
    private int mEmojiReplaceStrategy = 0;
    private boolean mEnabled = true;

    /* JADX INFO: Access modifiers changed from: package-private */
    public EmojiTextWatcher(EditText editText, boolean expectInitializedEmojiCompat) {
        this.mEditText = editText;
        this.mExpectInitializedEmojiCompat = expectInitializedEmojiCompat;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setMaxEmojiCount(int maxEmojiCount) {
        this.mMaxEmojiCount = maxEmojiCount;
    }

    int getMaxEmojiCount() {
        return this.mMaxEmojiCount;
    }

    int getEmojiReplaceStrategy() {
        return this.mEmojiReplaceStrategy;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEmojiReplaceStrategy(int replaceStrategy) {
        this.mEmojiReplaceStrategy = replaceStrategy;
    }

    @Override // android.text.TextWatcher
    public void onTextChanged(CharSequence charSequence, int start, int before, int after) {
        if (!this.mEditText.isInEditMode() && !shouldSkipForDisabledOrNotConfigured() && before <= after && (charSequence instanceof Spannable)) {
            switch (EmojiCompat.get().getLoadState()) {
                case 0:
                case 3:
                    EmojiCompat.get().registerInitCallback(getInitCallback());
                    return;
                case 1:
                    Spannable s = (Spannable) charSequence;
                    EmojiCompat.get().process(s, start, start + after, this.mMaxEmojiCount, this.mEmojiReplaceStrategy);
                    return;
                case 2:
                default:
                    return;
            }
        }
    }

    private boolean shouldSkipForDisabledOrNotConfigured() {
        return (this.mEnabled && (this.mExpectInitializedEmojiCompat || EmojiCompat.isConfigured())) ? false : true;
    }

    @Override // android.text.TextWatcher
    public void beforeTextChanged(CharSequence s, int start, int count, int after) {
    }

    @Override // android.text.TextWatcher
    public void afterTextChanged(Editable s) {
    }

    private EmojiCompat.InitCallback getInitCallback() {
        if (this.mInitCallback == null) {
            this.mInitCallback = new InitCallbackImpl(this.mEditText);
        }
        return this.mInitCallback;
    }

    public boolean isEnabled() {
        return this.mEnabled;
    }

    public void setEnabled(boolean isEnabled) {
        if (this.mEnabled != isEnabled) {
            if (this.mInitCallback != null) {
                EmojiCompat.get().unregisterInitCallback(this.mInitCallback);
            }
            this.mEnabled = isEnabled;
            if (isEnabled) {
                processTextOnEnablingEvent(this.mEditText, EmojiCompat.get().getLoadState());
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class InitCallbackImpl extends EmojiCompat.InitCallback {
        private final Reference<EditText> mViewRef;

        InitCallbackImpl(EditText editText) {
            this.mViewRef = new WeakReference(editText);
        }

        @Override // androidx.emoji2.text.EmojiCompat.InitCallback
        public void onInitialized() {
            super.onInitialized();
            EditText editText = this.mViewRef.get();
            EmojiTextWatcher.processTextOnEnablingEvent(editText, 1);
        }
    }

    static void processTextOnEnablingEvent(EditText editText, int currentLoadState) {
        if (currentLoadState == 1 && editText != null && editText.isAttachedToWindow()) {
            Editable text = editText.getEditableText();
            int selectionStart = Selection.getSelectionStart(text);
            int selectionEnd = Selection.getSelectionEnd(text);
            EmojiCompat.get().process(text);
            EmojiInputFilter.updateSelection(text, selectionStart, selectionEnd);
        }
    }
}
