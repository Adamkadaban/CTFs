package androidx.cardview.widget;

import android.content.Context;
import android.content.res.ColorStateList;
/* loaded from: classes.dex */
interface CardViewImpl {
    ColorStateList getBackgroundColor(CardViewDelegate cardViewDelegate);

    float getElevation(CardViewDelegate cardViewDelegate);

    float getMaxElevation(CardViewDelegate cardViewDelegate);

    float getMinHeight(CardViewDelegate cardViewDelegate);

    float getMinWidth(CardViewDelegate cardViewDelegate);

    float getRadius(CardViewDelegate cardViewDelegate);

    void initStatic();

    void initialize(CardViewDelegate cardViewDelegate, Context context, ColorStateList colorStateList, float f, float f2, float f3);

    void onCompatPaddingChanged(CardViewDelegate cardViewDelegate);

    void onPreventCornerOverlapChanged(CardViewDelegate cardViewDelegate);

    void setBackgroundColor(CardViewDelegate cardViewDelegate, ColorStateList colorStateList);

    void setElevation(CardViewDelegate cardViewDelegate, float f);

    void setMaxElevation(CardViewDelegate cardViewDelegate, float f);

    void setRadius(CardViewDelegate cardViewDelegate, float f);

    void updatePadding(CardViewDelegate cardViewDelegate);
}
