package androidx.emoji2.viewsintegration;

import android.os.Build;
import android.text.InputFilter;
import android.text.method.PasswordTransformationMethod;
import android.text.method.TransformationMethod;
import android.util.SparseArray;
import android.widget.TextView;
import androidx.core.util.Preconditions;
import androidx.emoji2.text.EmojiCompat;
/* loaded from: classes.dex */
public final class EmojiTextViewHelper {
    private final HelperInternal mHelper;

    public EmojiTextViewHelper(TextView textView) {
        this(textView, true);
    }

    public EmojiTextViewHelper(TextView textView, boolean expectInitializedEmojiCompat) {
        Preconditions.checkNotNull(textView, "textView cannot be null");
        if (Build.VERSION.SDK_INT < 19) {
            this.mHelper = new HelperInternal();
        } else if (!expectInitializedEmojiCompat) {
            this.mHelper = new SkippingHelper19(textView);
        } else {
            this.mHelper = new HelperInternal19(textView);
        }
    }

    public void updateTransformationMethod() {
        this.mHelper.updateTransformationMethod();
    }

    public InputFilter[] getFilters(InputFilter[] filters) {
        return this.mHelper.getFilters(filters);
    }

    public TransformationMethod wrapTransformationMethod(TransformationMethod transformationMethod) {
        return this.mHelper.wrapTransformationMethod(transformationMethod);
    }

    public void setEnabled(boolean enabled) {
        this.mHelper.setEnabled(enabled);
    }

    public void setAllCaps(boolean allCaps) {
        this.mHelper.setAllCaps(allCaps);
    }

    public boolean isEnabled() {
        return this.mHelper.isEnabled();
    }

    /* loaded from: classes.dex */
    static class HelperInternal {
        HelperInternal() {
        }

        void updateTransformationMethod() {
        }

        InputFilter[] getFilters(InputFilter[] filters) {
            return filters;
        }

        TransformationMethod wrapTransformationMethod(TransformationMethod transformationMethod) {
            return transformationMethod;
        }

        void setAllCaps(boolean allCaps) {
        }

        void setEnabled(boolean processEmoji) {
        }

        public boolean isEnabled() {
            return false;
        }
    }

    /* loaded from: classes.dex */
    private static class SkippingHelper19 extends HelperInternal {
        private final HelperInternal19 mHelperDelegate;

        SkippingHelper19(TextView textView) {
            this.mHelperDelegate = new HelperInternal19(textView);
        }

        private boolean skipBecauseEmojiCompatNotInitialized() {
            return !EmojiCompat.isConfigured();
        }

        @Override // androidx.emoji2.viewsintegration.EmojiTextViewHelper.HelperInternal
        void updateTransformationMethod() {
            if (skipBecauseEmojiCompatNotInitialized()) {
                return;
            }
            this.mHelperDelegate.updateTransformationMethod();
        }

        @Override // androidx.emoji2.viewsintegration.EmojiTextViewHelper.HelperInternal
        InputFilter[] getFilters(InputFilter[] filters) {
            if (skipBecauseEmojiCompatNotInitialized()) {
                return filters;
            }
            return this.mHelperDelegate.getFilters(filters);
        }

        @Override // androidx.emoji2.viewsintegration.EmojiTextViewHelper.HelperInternal
        TransformationMethod wrapTransformationMethod(TransformationMethod transformationMethod) {
            if (skipBecauseEmojiCompatNotInitialized()) {
                return transformationMethod;
            }
            return this.mHelperDelegate.wrapTransformationMethod(transformationMethod);
        }

        @Override // androidx.emoji2.viewsintegration.EmojiTextViewHelper.HelperInternal
        void setAllCaps(boolean allCaps) {
            if (skipBecauseEmojiCompatNotInitialized()) {
                return;
            }
            this.mHelperDelegate.setAllCaps(allCaps);
        }

        @Override // androidx.emoji2.viewsintegration.EmojiTextViewHelper.HelperInternal
        void setEnabled(boolean processEmoji) {
            if (skipBecauseEmojiCompatNotInitialized()) {
                this.mHelperDelegate.setEnabledUnsafe(processEmoji);
            } else {
                this.mHelperDelegate.setEnabled(processEmoji);
            }
        }

        @Override // androidx.emoji2.viewsintegration.EmojiTextViewHelper.HelperInternal
        public boolean isEnabled() {
            return this.mHelperDelegate.isEnabled();
        }
    }

    /* loaded from: classes.dex */
    private static class HelperInternal19 extends HelperInternal {
        private final EmojiInputFilter mEmojiInputFilter;
        private boolean mEnabled = true;
        private final TextView mTextView;

        HelperInternal19(TextView textView) {
            this.mTextView = textView;
            this.mEmojiInputFilter = new EmojiInputFilter(textView);
        }

        @Override // androidx.emoji2.viewsintegration.EmojiTextViewHelper.HelperInternal
        void updateTransformationMethod() {
            TransformationMethod tm = wrapTransformationMethod(this.mTextView.getTransformationMethod());
            this.mTextView.setTransformationMethod(tm);
        }

        private void updateFilters() {
            InputFilter[] oldFilters = this.mTextView.getFilters();
            this.mTextView.setFilters(getFilters(oldFilters));
        }

        @Override // androidx.emoji2.viewsintegration.EmojiTextViewHelper.HelperInternal
        InputFilter[] getFilters(InputFilter[] filters) {
            if (!this.mEnabled) {
                return removeEmojiInputFilterIfPresent(filters);
            }
            return addEmojiInputFilterIfMissing(filters);
        }

        private InputFilter[] addEmojiInputFilterIfMissing(InputFilter[] filters) {
            int count = filters.length;
            for (InputFilter inputFilter : filters) {
                if (inputFilter == this.mEmojiInputFilter) {
                    return filters;
                }
            }
            int i = filters.length;
            InputFilter[] newFilters = new InputFilter[i + 1];
            System.arraycopy(filters, 0, newFilters, 0, count);
            newFilters[count] = this.mEmojiInputFilter;
            return newFilters;
        }

        private InputFilter[] removeEmojiInputFilterIfPresent(InputFilter[] filters) {
            SparseArray<InputFilter> filterSet = getEmojiInputFilterPositionArray(filters);
            if (filterSet.size() == 0) {
                return filters;
            }
            int inCount = filters.length;
            int outCount = filters.length - filterSet.size();
            InputFilter[] result = new InputFilter[outCount];
            int destPosition = 0;
            for (int srcPosition = 0; srcPosition < inCount; srcPosition++) {
                if (filterSet.indexOfKey(srcPosition) < 0) {
                    result[destPosition] = filters[srcPosition];
                    destPosition++;
                }
            }
            return result;
        }

        private SparseArray<InputFilter> getEmojiInputFilterPositionArray(InputFilter[] filters) {
            SparseArray<InputFilter> result = new SparseArray<>(1);
            for (int pos = 0; pos < filters.length; pos++) {
                if (filters[pos] instanceof EmojiInputFilter) {
                    result.put(pos, filters[pos]);
                }
            }
            return result;
        }

        @Override // androidx.emoji2.viewsintegration.EmojiTextViewHelper.HelperInternal
        TransformationMethod wrapTransformationMethod(TransformationMethod transformationMethod) {
            if (this.mEnabled) {
                return wrapForEnabled(transformationMethod);
            }
            return unwrapForDisabled(transformationMethod);
        }

        private TransformationMethod unwrapForDisabled(TransformationMethod transformationMethod) {
            if (transformationMethod instanceof EmojiTransformationMethod) {
                EmojiTransformationMethod etm = (EmojiTransformationMethod) transformationMethod;
                return etm.getOriginalTransformationMethod();
            }
            return transformationMethod;
        }

        private TransformationMethod wrapForEnabled(TransformationMethod transformationMethod) {
            if (transformationMethod instanceof EmojiTransformationMethod) {
                return transformationMethod;
            }
            if (transformationMethod instanceof PasswordTransformationMethod) {
                return transformationMethod;
            }
            return new EmojiTransformationMethod(transformationMethod);
        }

        @Override // androidx.emoji2.viewsintegration.EmojiTextViewHelper.HelperInternal
        void setAllCaps(boolean allCaps) {
            if (allCaps) {
                updateTransformationMethod();
            }
        }

        @Override // androidx.emoji2.viewsintegration.EmojiTextViewHelper.HelperInternal
        void setEnabled(boolean enabled) {
            this.mEnabled = enabled;
            updateTransformationMethod();
            updateFilters();
        }

        @Override // androidx.emoji2.viewsintegration.EmojiTextViewHelper.HelperInternal
        public boolean isEnabled() {
            return this.mEnabled;
        }

        void setEnabledUnsafe(boolean processEmoji) {
            this.mEnabled = processEmoji;
        }
    }
}
