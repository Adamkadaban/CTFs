package com.example.timer;

import android.os.Bundle;
import android.os.CountDownTimer;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: MainActivity.kt */
@Metadata(d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0012\u0010\u001b\u001a\u00020\u001c2\b\u0010\u001d\u001a\u0004\u0018\u00010\u001eH\u0014J\u0010\u0010\u001f\u001a\u00020\u001c2\u0006\u0010 \u001a\u00020!H\u0002R\u001a\u0010\u0003\u001a\u00020\u0004X\u0086.¢\u0006\u000e\n\u0000\u001a\u0004\b\u0005\u0010\u0006\"\u0004\b\u0007\u0010\bR\u001a\u0010\t\u001a\u00020\u0004X\u0086.¢\u0006\u000e\n\u0000\u001a\u0004\b\n\u0010\u0006\"\u0004\b\u000b\u0010\bR\u001a\u0010\f\u001a\u00020\rX\u0086.¢\u0006\u000e\n\u0000\u001a\u0004\b\u000e\u0010\u000f\"\u0004\b\u0010\u0010\u0011R\u001a\u0010\u0012\u001a\u00020\u0004X\u0086.¢\u0006\u000e\n\u0000\u001a\u0004\b\u0013\u0010\u0006\"\u0004\b\u0014\u0010\bR\u001a\u0010\u0015\u001a\u00020\u0016X\u0086.¢\u0006\u000e\n\u0000\u001a\u0004\b\u0017\u0010\u0018\"\u0004\b\u0019\u0010\u001a¨\u0006\""}, d2 = {"Lcom/example/timer/MainActivity;", "Landroidx/appcompat/app/AppCompatActivity;", "()V", "hours", "Landroid/widget/EditText;", "getHours", "()Landroid/widget/EditText;", "setHours", "(Landroid/widget/EditText;)V", "minutes", "getMinutes", "setMinutes", "playbtn", "Landroid/widget/Button;", "getPlaybtn", "()Landroid/widget/Button;", "setPlaybtn", "(Landroid/widget/Button;)V", "seconds", "getSeconds", "setSeconds", "textView", "Landroid/widget/TextView;", "getTextView", "()Landroid/widget/TextView;", "setTextView", "(Landroid/widget/TextView;)V", "onCreate", "", "savedInstanceState", "Landroid/os/Bundle;", "startCountingDown", "starttime", "", "app_debug"}, k = 1, mv = {1, 6, 0}, xi = 48)
/* loaded from: classes3.dex */
public final class MainActivity extends AppCompatActivity {
    public EditText hours;
    public EditText minutes;
    public Button playbtn;
    public EditText seconds;
    public TextView textView;

    public final TextView getTextView() {
        TextView textView = this.textView;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("textView");
        return null;
    }

    public final void setTextView(TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.textView = textView;
    }

    public final Button getPlaybtn() {
        Button button = this.playbtn;
        if (button != null) {
            return button;
        }
        Intrinsics.throwUninitializedPropertyAccessException("playbtn");
        return null;
    }

    public final void setPlaybtn(Button button) {
        Intrinsics.checkNotNullParameter(button, "<set-?>");
        this.playbtn = button;
    }

    public final EditText getSeconds() {
        EditText editText = this.seconds;
        if (editText != null) {
            return editText;
        }
        Intrinsics.throwUninitializedPropertyAccessException("seconds");
        return null;
    }

    public final void setSeconds(EditText editText) {
        Intrinsics.checkNotNullParameter(editText, "<set-?>");
        this.seconds = editText;
    }

    public final EditText getMinutes() {
        EditText editText = this.minutes;
        if (editText != null) {
            return editText;
        }
        Intrinsics.throwUninitializedPropertyAccessException("minutes");
        return null;
    }

    public final void setMinutes(EditText editText) {
        Intrinsics.checkNotNullParameter(editText, "<set-?>");
        this.minutes = editText;
    }

    public final EditText getHours() {
        EditText editText = this.hours;
        if (editText != null) {
            return editText;
        }
        Intrinsics.throwUninitializedPropertyAccessException("hours");
        return null;
    }

    public final void setHours(EditText editText) {
        Intrinsics.checkNotNullParameter(editText, "<set-?>");
        this.hours = editText;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        View findViewById = findViewById(R.id.textView);
        Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(R.id.textView)");
        setTextView((TextView) findViewById);
        View findViewById2 = findViewById(R.id.play_btn);
        Intrinsics.checkNotNullExpressionValue(findViewById2, "findViewById(R.id.play_btn)");
        setPlaybtn((Button) findViewById2);
        View findViewById3 = findViewById(R.id.seconds_edt_txt);
        Intrinsics.checkNotNullExpressionValue(findViewById3, "findViewById(R.id.seconds_edt_txt)");
        setSeconds((EditText) findViewById3);
        View findViewById4 = findViewById(R.id.min_edt_txt);
        Intrinsics.checkNotNullExpressionValue(findViewById4, "findViewById(R.id.min_edt_txt)");
        setMinutes((EditText) findViewById4);
        View findViewById5 = findViewById(R.id.hours_edt_txt);
        Intrinsics.checkNotNullExpressionValue(findViewById5, "findViewById(R.id.hours_edt_txt)");
        setHours((EditText) findViewById5);
        getMinutes().setText("0");
        getSeconds().setText("0");
        getHours().setText("0");
        getPlaybtn().setOnClickListener(new View.OnClickListener() { // from class: com.example.timer.MainActivity$$ExternalSyntheticLambda0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.m30onCreate$lambda0(MainActivity.this, view);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: onCreate$lambda-0  reason: not valid java name */
    public static final void m30onCreate$lambda0(MainActivity this$0, View it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        String hoursentered = this$0.getHours().getText().toString();
        String minutesentered = this$0.getMinutes().getText().toString();
        String secondsentered = this$0.getSeconds().getText().toString();
        int actual_seconds = (Integer.parseInt(hoursentered) * 3600) + (Integer.parseInt(minutesentered) * 60) + Integer.parseInt(secondsentered);
        this$0.startCountingDown(actual_seconds * 1000);
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [com.example.timer.MainActivity$startCountingDown$1] */
    private final void startCountingDown(int starttime) {
        final long j = starttime;
        new CountDownTimer(j) { // from class: com.example.timer.MainActivity$startCountingDown$1
            @Override // android.os.CountDownTimer
            public void onTick(long millisUntilFinished) {
                long seconds_remaining = millisUntilFinished / 1000;
                if (seconds_remaining < 60) {
                    MainActivity.this.getSeconds().setText(String.valueOf(seconds_remaining));
                    MainActivity.this.getMinutes().setText("0");
                    MainActivity.this.getHours().setText("0");
                }
                if (seconds_remaining > 60 && seconds_remaining < 3600) {
                    int minutes_remaining = ((int) seconds_remaining) / 60;
                    MainActivity.this.getSeconds().setText(String.valueOf(seconds_remaining % 60));
                    MainActivity.this.getMinutes().setText(String.valueOf(minutes_remaining));
                    MainActivity.this.getHours().setText("0");
                }
                if (seconds_remaining >= 3600) {
                    long j2 = 3600;
                    long hours_remaining = seconds_remaining / j2;
                    long sec_remaining = seconds_remaining % j2;
                    int minutes_remaining2 = ((int) sec_remaining) / 60;
                    MainActivity.this.getSeconds().setText(String.valueOf(sec_remaining % 60));
                    MainActivity.this.getMinutes().setText(String.valueOf(minutes_remaining2));
                    MainActivity.this.getHours().setText(String.valueOf(hours_remaining));
                }
                MainActivity.this.getTextView().setText("seconds remaining: " + seconds_remaining);
            }

            @Override // android.os.CountDownTimer
            public void onFinish() {
                MainActivity.this.getTextView().setText("done!");
            }
        }.start();
    }
}
