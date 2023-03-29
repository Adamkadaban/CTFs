package androidx.emoji2.viewsintegration;

import android.text.InputFilter;
import android.text.Selection;
import android.text.Spannable;
import android.text.Spanned;
import android.widget.TextView;
import androidx.emoji2.text.EmojiCompat;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
/* loaded from: classes.dex */
final class EmojiInputFilter implements InputFilter {
    private EmojiCompat.InitCallback mInitCallback;
    private final TextView mTextView;

    /* JADX INFO: Access modifiers changed from: package-private */
    public EmojiInputFilter(TextView textView) {
        this.mTextView = textView;
    }

    @Override // android.text.InputFilter
    public CharSequence filter(CharSequence source, int sourceStart, int sourceEnd, Spanned dest, int destStart, int destEnd) {
        CharSequence text;
        if (this.mTextView.isInEditMode()) {
            return source;
        }
        switch (EmojiCompat.get().getLoadState()) {
            case 0:
            case 3:
                EmojiCompat.get().registerInitCallback(getInitCallback());
                return source;
            case 1:
                boolean process = true;
                if (destEnd == 0 && destStart == 0 && dest.length() == 0) {
                    CharSequence oldText = this.mTextView.getText();
                    if (source == oldText) {
                        process = false;
                    }
                }
                if (process && source != null) {
                    if (sourceStart == 0 && sourceEnd == source.length()) {
                        text = source;
                    } else {
                        text = source.subSequence(sourceStart, sourceEnd);
                    }
                    return EmojiCompat.get().process(text, 0, text.length());
                }
                return source;
            case 2:
            default:
                return source;
        }
    }

    private EmojiCompat.InitCallback getInitCallback() {
        if (this.mInitCallback == null) {
            this.mInitCallback = new InitCallbackImpl(this.mTextView, this);
        }
        return this.mInitCallback;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class InitCallbackImpl extends EmojiCompat.InitCallback {
        private final Reference<EmojiInputFilter> mEmojiInputFilterReference;
        private final Reference<TextView> mViewRef;

        InitCallbackImpl(TextView textView, EmojiInputFilter emojiInputFilter) {
            this.mViewRef = new WeakReference(textView);
            this.mEmojiInputFilterReference = new WeakReference(emojiInputFilter);
        }

        @Override // androidx.emoji2.text.EmojiCompat.InitCallback
        public void onInitialized() {
            super.onInitialized();
            TextView textView = this.mViewRef.get();
            InputFilter myInputFilter = this.mEmojiInputFilterReference.get();
            if (isInputFilterCurrentlyRegisteredOnTextView(textView, myInputFilter) && textView.isAttachedToWindow()) {
                CharSequence result = EmojiCompat.get().process(textView.getText());
                int selectionStart = Selection.getSelectionStart(result);
                int selectionEnd = Selection.getSelectionEnd(result);
                textView.setText(result);
                if (result instanceof Spannable) {
                    EmojiInputFilter.updateSelection((Spannable) result, selectionStart, selectionEnd);
                }
            }
        }

        private boolean isInputFilterCurrentlyRegisteredOnTextView(TextView textView, InputFilter myInputFilter) {
            InputFilter[] currentFilters;
            if (myInputFilter == null || textView == null || (currentFilters = textView.getFilters()) == null) {
                return false;
            }
            for (InputFilter inputFilter : currentFilters) {
                if (inputFilter == myInputFilter) {
                    return true;
                }
            }
            return false;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void updateSelection(Spannable spannable, int start, int end) {
        if (start >= 0 && end >= 0) {
            Selection.setSelection(spannable, start, end);
        } else if (start >= 0) {
            Selection.setSelection(spannable, start);
        } else if (end >= 0) {
            Selection.setSelection(spannable, end);
        }
    }
}
