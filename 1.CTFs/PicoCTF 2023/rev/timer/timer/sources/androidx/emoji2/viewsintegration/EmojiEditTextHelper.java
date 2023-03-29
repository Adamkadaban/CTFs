package androidx.emoji2.viewsintegration;

import android.os.Build;
import android.text.method.KeyListener;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.widget.EditText;
import androidx.core.util.Preconditions;
/* loaded from: classes.dex */
public final class EmojiEditTextHelper {
    private int mEmojiReplaceStrategy;
    private final HelperInternal mHelper;
    private int mMaxEmojiCount;

    public EmojiEditTextHelper(EditText editText) {
        this(editText, true);
    }

    public EmojiEditTextHelper(EditText editText, boolean expectInitializedEmojiCompat) {
        this.mMaxEmojiCount = Integer.MAX_VALUE;
        this.mEmojiReplaceStrategy = 0;
        Preconditions.checkNotNull(editText, "editText cannot be null");
        if (Build.VERSION.SDK_INT < 19) {
            this.mHelper = new HelperInternal();
        } else {
            this.mHelper = new HelperInternal19(editText, expectInitializedEmojiCompat);
        }
    }

    public void setMaxEmojiCount(int maxEmojiCount) {
        Preconditions.checkArgumentNonnegative(maxEmojiCount, "maxEmojiCount should be greater than 0");
        this.mMaxEmojiCount = maxEmojiCount;
        this.mHelper.setMaxEmojiCount(maxEmojiCount);
    }

    public int getMaxEmojiCount() {
        return this.mMaxEmojiCount;
    }

    public KeyListener getKeyListener(KeyListener keyListener) {
        return this.mHelper.getKeyListener(keyListener);
    }

    public InputConnection onCreateInputConnection(InputConnection inputConnection, EditorInfo outAttrs) {
        if (inputConnection == null) {
            return null;
        }
        return this.mHelper.onCreateInputConnection(inputConnection, outAttrs);
    }

    public void setEmojiReplaceStrategy(int replaceStrategy) {
        this.mEmojiReplaceStrategy = replaceStrategy;
        this.mHelper.setEmojiReplaceStrategy(replaceStrategy);
    }

    public int getEmojiReplaceStrategy() {
        return this.mEmojiReplaceStrategy;
    }

    public boolean isEnabled() {
        return this.mHelper.isEnabled();
    }

    public void setEnabled(boolean isEnabled) {
        this.mHelper.setEnabled(isEnabled);
    }

    /* loaded from: classes.dex */
    static class HelperInternal {
        HelperInternal() {
        }

        KeyListener getKeyListener(KeyListener keyListener) {
            return keyListener;
        }

        InputConnection onCreateInputConnection(InputConnection inputConnection, EditorInfo outAttrs) {
            return inputConnection;
        }

        void setMaxEmojiCount(int maxEmojiCount) {
        }

        void setEmojiReplaceStrategy(int replaceStrategy) {
        }

        void setEnabled(boolean isEnabled) {
        }

        boolean isEnabled() {
            return false;
        }
    }

    /* loaded from: classes.dex */
    private static class HelperInternal19 extends HelperInternal {
        private final EditText mEditText;
        private final EmojiTextWatcher mTextWatcher;

        HelperInternal19(EditText editText, boolean expectInitializedEmojiCompat) {
            this.mEditText = editText;
            EmojiTextWatcher emojiTextWatcher = new EmojiTextWatcher(editText, expectInitializedEmojiCompat);
            this.mTextWatcher = emojiTextWatcher;
            editText.addTextChangedListener(emojiTextWatcher);
            editText.setEditableFactory(EmojiEditableFactory.getInstance());
        }

        @Override // androidx.emoji2.viewsintegration.EmojiEditTextHelper.HelperInternal
        void setMaxEmojiCount(int maxEmojiCount) {
            this.mTextWatcher.setMaxEmojiCount(maxEmojiCount);
        }

        @Override // androidx.emoji2.viewsintegration.EmojiEditTextHelper.HelperInternal
        void setEmojiReplaceStrategy(int replaceStrategy) {
            this.mTextWatcher.setEmojiReplaceStrategy(replaceStrategy);
        }

        @Override // androidx.emoji2.viewsintegration.EmojiEditTextHelper.HelperInternal
        KeyListener getKeyListener(KeyListener keyListener) {
            if (keyListener instanceof EmojiKeyListener) {
                return keyListener;
            }
            if (keyListener == null) {
                return null;
            }
            return new EmojiKeyListener(keyListener);
        }

        @Override // androidx.emoji2.viewsintegration.EmojiEditTextHelper.HelperInternal
        InputConnection onCreateInputConnection(InputConnection inputConnection, EditorInfo outAttrs) {
            if (inputConnection instanceof EmojiInputConnection) {
                return inputConnection;
            }
            return new EmojiInputConnection(this.mEditText, inputConnection, outAttrs);
        }

        @Override // androidx.emoji2.viewsintegration.EmojiEditTextHelper.HelperInternal
        void setEnabled(boolean isEnabled) {
            this.mTextWatcher.setEnabled(isEnabled);
        }

        @Override // androidx.emoji2.viewsintegration.EmojiEditTextHelper.HelperInternal
        boolean isEnabled() {
            return this.mTextWatcher.isEnabled();
        }
    }
}
