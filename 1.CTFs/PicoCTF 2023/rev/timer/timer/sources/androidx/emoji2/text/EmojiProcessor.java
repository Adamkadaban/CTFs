package androidx.emoji2.text;

import android.os.Build;
import android.text.Editable;
import android.text.Selection;
import android.text.Spannable;
import android.text.TextPaint;
import android.text.method.MetaKeyKeyListener;
import android.view.KeyEvent;
import android.view.inputmethod.InputConnection;
import androidx.core.graphics.PaintCompat;
import androidx.emoji2.text.EmojiCompat;
import androidx.emoji2.text.MetadataRepo;
import java.util.Arrays;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public final class EmojiProcessor {
    private static final int ACTION_ADVANCE_BOTH = 1;
    private static final int ACTION_ADVANCE_END = 2;
    private static final int ACTION_FLUSH = 3;
    private final int[] mEmojiAsDefaultStyleExceptions;
    private EmojiCompat.GlyphChecker mGlyphChecker;
    private final MetadataRepo mMetadataRepo;
    private final EmojiCompat.SpanFactory mSpanFactory;
    private final boolean mUseEmojiAsDefaultStyle;

    /* JADX INFO: Access modifiers changed from: package-private */
    public EmojiProcessor(MetadataRepo metadataRepo, EmojiCompat.SpanFactory spanFactory, EmojiCompat.GlyphChecker glyphChecker, boolean useEmojiAsDefaultStyle, int[] emojiAsDefaultStyleExceptions) {
        this.mSpanFactory = spanFactory;
        this.mMetadataRepo = metadataRepo;
        this.mGlyphChecker = glyphChecker;
        this.mUseEmojiAsDefaultStyle = useEmojiAsDefaultStyle;
        this.mEmojiAsDefaultStyleExceptions = emojiAsDefaultStyleExceptions;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public EmojiMetadata getEmojiMetadata(CharSequence charSequence) {
        ProcessorSm sm = new ProcessorSm(this.mMetadataRepo.getRootNode(), this.mUseEmojiAsDefaultStyle, this.mEmojiAsDefaultStyleExceptions);
        int end = charSequence.length();
        int currentOffset = 0;
        while (currentOffset < end) {
            int codePoint = Character.codePointAt(charSequence, currentOffset);
            int action = sm.check(codePoint);
            if (action != 2) {
                return null;
            }
            currentOffset += Character.charCount(codePoint);
        }
        if (!sm.isInFlushableState()) {
            return null;
        }
        return sm.getCurrentMetadata();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x0114, code lost:
        ((androidx.emoji2.text.SpannableBuilder) r10).endBatchEdit();
     */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0043 A[Catch: all -> 0x011b, TryCatch #0 {all -> 0x011b, blocks: (B:7:0x000d, B:10:0x0012, B:12:0x0016, B:14:0x0025, B:17:0x0032, B:19:0x003c, B:21:0x003f, B:23:0x0043, B:25:0x004f, B:26:0x0052, B:28:0x0061, B:34:0x0070, B:35:0x007f, B:38:0x0098, B:39:0x009c, B:42:0x00a2, B:45:0x00ae, B:46:0x00b4, B:48:0x00bf, B:50:0x00c6, B:51:0x00cc, B:53:0x00d8, B:55:0x00de, B:59:0x00e8, B:62:0x00f4, B:63:0x00fa, B:15:0x002c), top: B:79:0x000d }] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00bf A[Catch: all -> 0x011b, TryCatch #0 {all -> 0x011b, blocks: (B:7:0x000d, B:10:0x0012, B:12:0x0016, B:14:0x0025, B:17:0x0032, B:19:0x003c, B:21:0x003f, B:23:0x0043, B:25:0x004f, B:26:0x0052, B:28:0x0061, B:34:0x0070, B:35:0x007f, B:38:0x0098, B:39:0x009c, B:42:0x00a2, B:45:0x00ae, B:46:0x00b4, B:48:0x00bf, B:50:0x00c6, B:51:0x00cc, B:53:0x00d8, B:55:0x00de, B:59:0x00e8, B:62:0x00f4, B:63:0x00fa, B:15:0x002c), top: B:79:0x000d }] */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00cc A[Catch: all -> 0x011b, TryCatch #0 {all -> 0x011b, blocks: (B:7:0x000d, B:10:0x0012, B:12:0x0016, B:14:0x0025, B:17:0x0032, B:19:0x003c, B:21:0x003f, B:23:0x0043, B:25:0x004f, B:26:0x0052, B:28:0x0061, B:34:0x0070, B:35:0x007f, B:38:0x0098, B:39:0x009c, B:42:0x00a2, B:45:0x00ae, B:46:0x00b4, B:48:0x00bf, B:50:0x00c6, B:51:0x00cc, B:53:0x00d8, B:55:0x00de, B:59:0x00e8, B:62:0x00f4, B:63:0x00fa, B:15:0x002c), top: B:79:0x000d }] */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00f4 A[Catch: all -> 0x011b, TryCatch #0 {all -> 0x011b, blocks: (B:7:0x000d, B:10:0x0012, B:12:0x0016, B:14:0x0025, B:17:0x0032, B:19:0x003c, B:21:0x003f, B:23:0x0043, B:25:0x004f, B:26:0x0052, B:28:0x0061, B:34:0x0070, B:35:0x007f, B:38:0x0098, B:39:0x009c, B:42:0x00a2, B:45:0x00ae, B:46:0x00b4, B:48:0x00bf, B:50:0x00c6, B:51:0x00cc, B:53:0x00d8, B:55:0x00de, B:59:0x00e8, B:62:0x00f4, B:63:0x00fa, B:15:0x002c), top: B:79:0x000d }] */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0105  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0107  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x010a A[DONT_GENERATE] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.CharSequence process(java.lang.CharSequence r10, int r11, int r12, int r13, boolean r14) {
        /*
            Method dump skipped, instructions count: 304
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.emoji2.text.EmojiProcessor.process(java.lang.CharSequence, int, int, int, boolean):java.lang.CharSequence");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean handleOnKeyDown(Editable editable, int keyCode, KeyEvent event) {
        boolean handled;
        switch (keyCode) {
            case 67:
                handled = delete(editable, event, false);
                break;
            case 112:
                handled = delete(editable, event, true);
                break;
            default:
                handled = false;
                break;
        }
        if (handled) {
            MetaKeyKeyListener.adjustMetaAfterKeypress(editable);
            return true;
        }
        return false;
    }

    private static boolean delete(Editable content, KeyEvent event, boolean forwardDelete) {
        EmojiSpan[] spans;
        if (hasModifiers(event)) {
            return false;
        }
        int start = Selection.getSelectionStart(content);
        int end = Selection.getSelectionEnd(content);
        if (!hasInvalidSelection(start, end) && (spans = (EmojiSpan[]) content.getSpans(start, end, EmojiSpan.class)) != null && spans.length > 0) {
            for (EmojiSpan span : spans) {
                int spanStart = content.getSpanStart(span);
                int spanEnd = content.getSpanEnd(span);
                if ((forwardDelete && spanStart == start) || ((!forwardDelete && spanEnd == start) || (start > spanStart && start < spanEnd))) {
                    content.delete(spanStart, spanEnd);
                    return true;
                }
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean handleDeleteSurroundingText(InputConnection inputConnection, Editable editable, int beforeLength, int afterLength, boolean inCodePoints) {
        int start;
        int end;
        if (editable == null || inputConnection == null || beforeLength < 0 || afterLength < 0) {
            return false;
        }
        int selectionStart = Selection.getSelectionStart(editable);
        int selectionEnd = Selection.getSelectionEnd(editable);
        if (hasInvalidSelection(selectionStart, selectionEnd)) {
            return false;
        }
        if (inCodePoints) {
            start = CodepointIndexFinder.findIndexBackward(editable, selectionStart, Math.max(beforeLength, 0));
            end = CodepointIndexFinder.findIndexForward(editable, selectionEnd, Math.max(afterLength, 0));
            if (start == -1 || end == -1) {
                return false;
            }
        } else {
            int start2 = selectionStart - beforeLength;
            start = Math.max(start2, 0);
            end = Math.min(selectionEnd + afterLength, editable.length());
        }
        EmojiSpan[] spans = (EmojiSpan[]) editable.getSpans(start, end, EmojiSpan.class);
        if (spans == null || spans.length <= 0) {
            return false;
        }
        for (EmojiSpan span : spans) {
            int spanStart = editable.getSpanStart(span);
            int spanEnd = editable.getSpanEnd(span);
            start = Math.min(spanStart, start);
            end = Math.max(spanEnd, end);
        }
        int start3 = Math.max(start, 0);
        int start4 = editable.length();
        int end2 = Math.min(end, start4);
        inputConnection.beginBatchEdit();
        editable.delete(start3, end2);
        inputConnection.endBatchEdit();
        return true;
    }

    private static boolean hasInvalidSelection(int start, int end) {
        return start == -1 || end == -1 || start != end;
    }

    private static boolean hasModifiers(KeyEvent event) {
        return !KeyEvent.metaStateHasNoModifiers(event.getMetaState());
    }

    private void addEmoji(Spannable spannable, EmojiMetadata metadata, int start, int end) {
        EmojiSpan span = this.mSpanFactory.createSpan(metadata);
        spannable.setSpan(span, start, end, 33);
    }

    private boolean hasGlyph(CharSequence charSequence, int start, int end, EmojiMetadata metadata) {
        if (metadata.getHasGlyph() == 0) {
            boolean hasGlyph = this.mGlyphChecker.hasGlyph(charSequence, start, end, metadata.getSdkAdded());
            metadata.setHasGlyph(hasGlyph);
        }
        return metadata.getHasGlyph() == 2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class ProcessorSm {
        private static final int STATE_DEFAULT = 1;
        private static final int STATE_WALKING = 2;
        private int mCurrentDepth;
        private MetadataRepo.Node mCurrentNode;
        private final int[] mEmojiAsDefaultStyleExceptions;
        private MetadataRepo.Node mFlushNode;
        private int mLastCodepoint;
        private final MetadataRepo.Node mRootNode;
        private int mState = 1;
        private final boolean mUseEmojiAsDefaultStyle;

        ProcessorSm(MetadataRepo.Node rootNode, boolean useEmojiAsDefaultStyle, int[] emojiAsDefaultStyleExceptions) {
            this.mRootNode = rootNode;
            this.mCurrentNode = rootNode;
            this.mUseEmojiAsDefaultStyle = useEmojiAsDefaultStyle;
            this.mEmojiAsDefaultStyleExceptions = emojiAsDefaultStyleExceptions;
        }

        int check(int codePoint) {
            int action;
            MetadataRepo.Node node = this.mCurrentNode.get(codePoint);
            switch (this.mState) {
                case 2:
                    if (node != null) {
                        this.mCurrentNode = node;
                        this.mCurrentDepth++;
                        action = 2;
                        break;
                    } else if (isTextStyle(codePoint)) {
                        action = reset();
                        break;
                    } else if (isEmojiStyle(codePoint)) {
                        action = 2;
                        break;
                    } else if (this.mCurrentNode.getData() != null) {
                        if (this.mCurrentDepth == 1) {
                            if (shouldUseEmojiPresentationStyleForSingleCodepoint()) {
                                this.mFlushNode = this.mCurrentNode;
                                action = 3;
                                reset();
                                break;
                            } else {
                                action = reset();
                                break;
                            }
                        } else {
                            this.mFlushNode = this.mCurrentNode;
                            action = 3;
                            reset();
                            break;
                        }
                    } else {
                        action = reset();
                        break;
                    }
                default:
                    if (node == null) {
                        action = reset();
                        break;
                    } else {
                        this.mState = 2;
                        this.mCurrentNode = node;
                        this.mCurrentDepth = 1;
                        action = 2;
                        break;
                    }
            }
            this.mLastCodepoint = codePoint;
            return action;
        }

        private int reset() {
            this.mState = 1;
            this.mCurrentNode = this.mRootNode;
            this.mCurrentDepth = 0;
            return 1;
        }

        EmojiMetadata getFlushMetadata() {
            return this.mFlushNode.getData();
        }

        EmojiMetadata getCurrentMetadata() {
            return this.mCurrentNode.getData();
        }

        boolean isInFlushableState() {
            return this.mState == 2 && this.mCurrentNode.getData() != null && (this.mCurrentDepth > 1 || shouldUseEmojiPresentationStyleForSingleCodepoint());
        }

        private boolean shouldUseEmojiPresentationStyleForSingleCodepoint() {
            if (this.mCurrentNode.getData().isDefaultEmoji() || isEmojiStyle(this.mLastCodepoint)) {
                return true;
            }
            if (this.mUseEmojiAsDefaultStyle) {
                if (this.mEmojiAsDefaultStyleExceptions == null) {
                    return true;
                }
                int codepoint = this.mCurrentNode.getData().getCodepointAt(0);
                int index = Arrays.binarySearch(this.mEmojiAsDefaultStyleExceptions, codepoint);
                if (index < 0) {
                    return true;
                }
            }
            return false;
        }

        private static boolean isEmojiStyle(int codePoint) {
            return codePoint == 65039;
        }

        private static boolean isTextStyle(int codePoint) {
            return codePoint == 65038;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static final class CodepointIndexFinder {
        private static final int INVALID_INDEX = -1;

        private CodepointIndexFinder() {
        }

        static int findIndexBackward(CharSequence cs, int from, int numCodePoints) {
            int currentIndex = from;
            boolean waitingHighSurrogate = false;
            int length = cs.length();
            if (currentIndex < 0 || length < currentIndex || numCodePoints < 0) {
                return -1;
            }
            int remainingCodePoints = numCodePoints;
            while (remainingCodePoints != 0) {
                currentIndex--;
                if (currentIndex < 0) {
                    if (waitingHighSurrogate) {
                        return -1;
                    }
                    return 0;
                }
                char c = cs.charAt(currentIndex);
                if (waitingHighSurrogate) {
                    if (!Character.isHighSurrogate(c)) {
                        return -1;
                    }
                    waitingHighSurrogate = false;
                    remainingCodePoints--;
                } else if (!Character.isSurrogate(c)) {
                    remainingCodePoints--;
                } else if (Character.isHighSurrogate(c)) {
                    return -1;
                } else {
                    waitingHighSurrogate = true;
                }
            }
            return currentIndex;
        }

        static int findIndexForward(CharSequence cs, int from, int numCodePoints) {
            int currentIndex = from;
            boolean waitingLowSurrogate = false;
            int length = cs.length();
            if (currentIndex < 0 || length < currentIndex || numCodePoints < 0) {
                return -1;
            }
            int remainingCodePoints = numCodePoints;
            while (remainingCodePoints != 0) {
                if (currentIndex >= length) {
                    if (waitingLowSurrogate) {
                        return -1;
                    }
                    return length;
                }
                char c = cs.charAt(currentIndex);
                if (waitingLowSurrogate) {
                    if (!Character.isLowSurrogate(c)) {
                        return -1;
                    }
                    remainingCodePoints--;
                    waitingLowSurrogate = false;
                    currentIndex++;
                } else if (!Character.isSurrogate(c)) {
                    remainingCodePoints--;
                    currentIndex++;
                } else if (Character.isLowSurrogate(c)) {
                    return -1;
                } else {
                    waitingLowSurrogate = true;
                    currentIndex++;
                }
            }
            return currentIndex;
        }
    }

    /* loaded from: classes.dex */
    public static class DefaultGlyphChecker implements EmojiCompat.GlyphChecker {
        private static final int PAINT_TEXT_SIZE = 10;
        private static final ThreadLocal<StringBuilder> sStringBuilder = new ThreadLocal<>();
        private final TextPaint mTextPaint;

        /* JADX INFO: Access modifiers changed from: package-private */
        public DefaultGlyphChecker() {
            TextPaint textPaint = new TextPaint();
            this.mTextPaint = textPaint;
            textPaint.setTextSize(10.0f);
        }

        @Override // androidx.emoji2.text.EmojiCompat.GlyphChecker
        public boolean hasGlyph(CharSequence charSequence, int start, int end, int sdkAdded) {
            if (Build.VERSION.SDK_INT >= 23 || sdkAdded <= Build.VERSION.SDK_INT) {
                StringBuilder builder = getStringBuilder();
                builder.setLength(0);
                while (start < end) {
                    builder.append(charSequence.charAt(start));
                    start++;
                }
                return PaintCompat.hasGlyph(this.mTextPaint, builder.toString());
            }
            return false;
        }

        private static StringBuilder getStringBuilder() {
            ThreadLocal<StringBuilder> threadLocal = sStringBuilder;
            if (threadLocal.get() == null) {
                threadLocal.set(new StringBuilder());
            }
            return threadLocal.get();
        }
    }
}
