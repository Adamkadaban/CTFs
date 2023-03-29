package com.google.android.material.bottomsheet;

import android.app.Dialog;
import android.os.Bundle;
import android.view.View;
import androidx.appcompat.app.AppCompatDialogFragment;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
/* loaded from: classes.dex */
public class BottomSheetDialogFragment extends AppCompatDialogFragment {
    private boolean waitingForDismissAllowingStateLoss;

    @Override // androidx.appcompat.app.AppCompatDialogFragment, androidx.fragment.app.DialogFragment
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        return new BottomSheetDialog(getContext(), getTheme());
    }

    @Override // androidx.fragment.app.DialogFragment
    public void dismiss() {
        if (!tryDismissWithAnimation(false)) {
            super.dismiss();
        }
    }

    @Override // androidx.fragment.app.DialogFragment
    public void dismissAllowingStateLoss() {
        if (!tryDismissWithAnimation(true)) {
            super.dismissAllowingStateLoss();
        }
    }

    private boolean tryDismissWithAnimation(boolean allowingStateLoss) {
        Dialog baseDialog = getDialog();
        if (baseDialog instanceof BottomSheetDialog) {
            BottomSheetDialog dialog = (BottomSheetDialog) baseDialog;
            BottomSheetBehavior<?> behavior = dialog.getBehavior();
            if (behavior.isHideable() && dialog.getDismissWithAnimation()) {
                dismissWithAnimation(behavior, allowingStateLoss);
                return true;
            }
            return false;
        }
        return false;
    }

    private void dismissWithAnimation(BottomSheetBehavior<?> behavior, boolean allowingStateLoss) {
        this.waitingForDismissAllowingStateLoss = allowingStateLoss;
        if (behavior.getState() == 5) {
            dismissAfterAnimation();
            return;
        }
        if (getDialog() instanceof BottomSheetDialog) {
            ((BottomSheetDialog) getDialog()).removeDefaultCallback();
        }
        behavior.addBottomSheetCallback(new BottomSheetDismissCallback());
        behavior.setState(5);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void dismissAfterAnimation() {
        if (this.waitingForDismissAllowingStateLoss) {
            super.dismissAllowingStateLoss();
        } else {
            super.dismiss();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class BottomSheetDismissCallback extends BottomSheetBehavior.BottomSheetCallback {
        private BottomSheetDismissCallback() {
        }

        @Override // com.google.android.material.bottomsheet.BottomSheetBehavior.BottomSheetCallback
        public void onStateChanged(View bottomSheet, int newState) {
            if (newState == 5) {
                BottomSheetDialogFragment.this.dismissAfterAnimation();
            }
        }

        @Override // com.google.android.material.bottomsheet.BottomSheetBehavior.BottomSheetCallback
        public void onSlide(View bottomSheet, float slideOffset) {
        }
    }
}
