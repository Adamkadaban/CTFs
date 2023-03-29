package androidx.emoji2.viewsintegration;

import android.text.Editable;
import android.text.method.KeyListener;
import android.view.KeyEvent;
import android.view.View;
import androidx.emoji2.text.EmojiCompat;
/* loaded from: classes.dex */
final class EmojiKeyListener implements KeyListener {
    private final EmojiCompatHandleKeyDownHelper mEmojiCompatHandleKeyDownHelper;
    private final KeyListener mKeyListener;

    /* JADX INFO: Access modifiers changed from: package-private */
    public EmojiKeyListener(KeyListener keyListener) {
        this(keyListener, new EmojiCompatHandleKeyDownHelper());
    }

    EmojiKeyListener(KeyListener keyListener, EmojiCompatHandleKeyDownHelper emojiCompatKeydownHelper) {
        this.mKeyListener = keyListener;
        this.mEmojiCompatHandleKeyDownHelper = emojiCompatKeydownHelper;
    }

    @Override // android.text.method.KeyListener
    public int getInputType() {
        return this.mKeyListener.getInputType();
    }

    @Override // android.text.method.KeyListener
    public boolean onKeyDown(View view, Editable content, int keyCode, KeyEvent event) {
        boolean result = this.mEmojiCompatHandleKeyDownHelper.handleKeyDown(content, keyCode, event);
        return result || this.mKeyListener.onKeyDown(view, content, keyCode, event);
    }

    @Override // android.text.method.KeyListener
    public boolean onKeyUp(View view, Editable text, int keyCode, KeyEvent event) {
        return this.mKeyListener.onKeyUp(view, text, keyCode, event);
    }

    @Override // android.text.method.KeyListener
    public boolean onKeyOther(View view, Editable text, KeyEvent event) {
        return this.mKeyListener.onKeyOther(view, text, event);
    }

    @Override // android.text.method.KeyListener
    public void clearMetaKeyState(View view, Editable content, int states) {
        this.mKeyListener.clearMetaKeyState(view, content, states);
    }

    /* loaded from: classes.dex */
    public static class EmojiCompatHandleKeyDownHelper {
        public boolean handleKeyDown(Editable editable, int keyCode, KeyEvent event) {
            return EmojiCompat.handleOnKeyDown(editable, keyCode, event);
        }
    }
}
