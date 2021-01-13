.class public La/b/p/w;
.super Landroid/widget/Spinner;
.source ""


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/b/p/w$d;,
        La/b/p/w$b;,
        La/b/p/w$f;,
        La/b/p/w$c;,
        La/b/p/w$e;
    }
.end annotation


# static fields
.field public static final j:[I


# instance fields
.field public final b:La/b/p/e;

.field public final c:Landroid/content/Context;

.field public d:La/b/p/h0;

.field public e:Landroid/widget/SpinnerAdapter;

.field public final f:Z

.field public g:La/b/p/w$f;

.field public h:I

.field public final i:Landroid/graphics/Rect;


# direct methods
.method public static constructor <clinit>()V
    .locals 3

    const/4 v0, 0x1

    new-array v0, v0, [I

    const/4 v1, 0x0

    const v2, 0x10102f1

    aput v2, v0, v1

    sput-object v0, La/b/p/w;->j:[I

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .locals 8

    .line 1
    invoke-direct {p0, p1, p2, p3}, Landroid/widget/Spinner;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    new-instance v0, Landroid/graphics/Rect;

    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    iput-object v0, p0, La/b/p/w;->i:Landroid/graphics/Rect;

    invoke-virtual {p0}, Landroid/widget/Spinner;->getContext()Landroid/content/Context;

    move-result-object v0

    invoke-static {p0, v0}, La/b/p/s0;->a(Landroid/view/View;Landroid/content/Context;)V

    sget-object v0, La/b/j;->Spinner:[I

    const/4 v1, 0x0

    .line 2
    invoke-virtual {p1, p2, v0, p3, v1}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    move-result-object v0

    .line 3
    new-instance v2, La/b/p/e;

    invoke-direct {v2, p0}, La/b/p/e;-><init>(Landroid/view/View;)V

    iput-object v2, p0, La/b/p/w;->b:La/b/p/e;

    sget v2, La/b/j;->Spinner_popupTheme:I

    .line 4
    invoke-virtual {v0, v2, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v2

    if-eqz v2, :cond_0

    .line 5
    new-instance v3, La/b/o/c;

    invoke-direct {v3, p1, v2}, La/b/o/c;-><init>(Landroid/content/Context;I)V

    iput-object v3, p0, La/b/p/w;->c:Landroid/content/Context;

    goto :goto_0

    :cond_0
    iput-object p1, p0, La/b/p/w;->c:Landroid/content/Context;

    :goto_0
    const/4 v2, 0x0

    const/4 v3, -0x1

    :try_start_0
    sget-object v4, La/b/p/w;->j:[I

    invoke-virtual {p1, p2, v4, p3, v1}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    move-result-object v4
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    :try_start_1
    invoke-virtual {v4, v1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v5

    if-eqz v5, :cond_1

    invoke-virtual {v4, v1, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v3
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_2

    :catchall_0
    move-exception p1

    move-object v2, v4

    goto/16 :goto_4

    :catch_0
    move-exception v5

    goto :goto_1

    :catchall_1
    move-exception p1

    goto/16 :goto_4

    :catch_1
    move-exception v4

    move-object v5, v4

    move-object v4, v2

    :goto_1
    :try_start_2
    const-string v6, "AppCompatSpinner"

    const-string v7, "Could not read android:spinnerMode"

    invoke-static {v6, v7, v5}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    if-eqz v4, :cond_2

    :cond_1
    :goto_2
    invoke-virtual {v4}, Landroid/content/res/TypedArray;->recycle()V

    :cond_2
    const/4 v4, 0x1

    if-eqz v3, :cond_4

    if-eq v3, v4, :cond_3

    goto :goto_3

    :cond_3
    new-instance v3, La/b/p/w$d;

    iget-object v5, p0, La/b/p/w;->c:Landroid/content/Context;

    invoke-direct {v3, p0, v5, p2, p3}, La/b/p/w$d;-><init>(La/b/p/w;Landroid/content/Context;Landroid/util/AttributeSet;I)V

    iget-object v5, p0, La/b/p/w;->c:Landroid/content/Context;

    sget-object v6, La/b/j;->Spinner:[I

    invoke-static {v5, p2, v6, p3, v1}, La/b/p/x0;->o(Landroid/content/Context;Landroid/util/AttributeSet;[III)La/b/p/x0;

    move-result-object v1

    sget v5, La/b/j;->Spinner_android_dropDownWidth:I

    const/4 v6, -0x2

    invoke-virtual {v1, v5, v6}, La/b/p/x0;->i(II)I

    move-result v5

    iput v5, p0, La/b/p/w;->h:I

    sget v5, La/b/j;->Spinner_android_popupBackground:I

    invoke-virtual {v1, v5}, La/b/p/x0;->e(I)Landroid/graphics/drawable/Drawable;

    move-result-object v5

    .line 6
    iget-object v6, v3, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v6, v5}, Landroid/widget/PopupWindow;->setBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 7
    sget v5, La/b/j;->Spinner_android_prompt:I

    .line 8
    invoke-virtual {v0, v5}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v5

    .line 9
    iput-object v5, v3, La/b/p/w$d;->F:Ljava/lang/CharSequence;

    .line 10
    iget-object v1, v1, La/b/p/x0;->b:Landroid/content/res/TypedArray;

    invoke-virtual {v1}, Landroid/content/res/TypedArray;->recycle()V

    .line 11
    iput-object v3, p0, La/b/p/w;->g:La/b/p/w$f;

    new-instance v1, La/b/p/v;

    invoke-direct {v1, p0, p0, v3}, La/b/p/v;-><init>(La/b/p/w;Landroid/view/View;La/b/p/w$d;)V

    iput-object v1, p0, La/b/p/w;->d:La/b/p/h0;

    goto :goto_3

    :cond_4
    new-instance v1, La/b/p/w$b;

    invoke-direct {v1, p0}, La/b/p/w$b;-><init>(La/b/p/w;)V

    iput-object v1, p0, La/b/p/w;->g:La/b/p/w$f;

    sget v3, La/b/j;->Spinner_android_prompt:I

    .line 12
    invoke-virtual {v0, v3}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v3

    .line 13
    invoke-virtual {v1, v3}, La/b/p/w$b;->h(Ljava/lang/CharSequence;)V

    :goto_3
    sget v1, La/b/j;->Spinner_android_entries:I

    .line 14
    invoke-virtual {v0, v1}, Landroid/content/res/TypedArray;->getTextArray(I)[Ljava/lang/CharSequence;

    move-result-object v1

    if-eqz v1, :cond_5

    .line 15
    new-instance v3, Landroid/widget/ArrayAdapter;

    const v5, 0x1090008

    invoke-direct {v3, p1, v5, v1}, Landroid/widget/ArrayAdapter;-><init>(Landroid/content/Context;I[Ljava/lang/Object;)V

    sget p1, La/b/g;->support_simple_spinner_dropdown_item:I

    invoke-virtual {v3, p1}, Landroid/widget/ArrayAdapter;->setDropDownViewResource(I)V

    invoke-virtual {p0, v3}, La/b/p/w;->setAdapter(Landroid/widget/SpinnerAdapter;)V

    .line 16
    :cond_5
    invoke-virtual {v0}, Landroid/content/res/TypedArray;->recycle()V

    .line 17
    iput-boolean v4, p0, La/b/p/w;->f:Z

    iget-object p1, p0, La/b/p/w;->e:Landroid/widget/SpinnerAdapter;

    if-eqz p1, :cond_6

    invoke-virtual {p0, p1}, La/b/p/w;->setAdapter(Landroid/widget/SpinnerAdapter;)V

    iput-object v2, p0, La/b/p/w;->e:Landroid/widget/SpinnerAdapter;

    :cond_6
    iget-object p1, p0, La/b/p/w;->b:La/b/p/e;

    invoke-virtual {p1, p2, p3}, La/b/p/e;->d(Landroid/util/AttributeSet;I)V

    return-void

    :goto_4
    if-eqz v2, :cond_7

    invoke-virtual {v2}, Landroid/content/res/TypedArray;->recycle()V

    :cond_7
    throw p1
.end method


# virtual methods
.method public a(Landroid/widget/SpinnerAdapter;Landroid/graphics/drawable/Drawable;)I
    .locals 10

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return v0

    :cond_0
    invoke-virtual {p0}, Landroid/widget/Spinner;->getMeasuredWidth()I

    move-result v1

    invoke-static {v1, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v1

    invoke-virtual {p0}, Landroid/widget/Spinner;->getMeasuredHeight()I

    move-result v2

    invoke-static {v2, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v2

    invoke-virtual {p0}, Landroid/widget/Spinner;->getSelectedItemPosition()I

    move-result v3

    invoke-static {v0, v3}, Ljava/lang/Math;->max(II)I

    move-result v3

    invoke-interface {p1}, Landroid/widget/SpinnerAdapter;->getCount()I

    move-result v4

    add-int/lit8 v5, v3, 0xf

    invoke-static {v4, v5}, Ljava/lang/Math;->min(II)I

    move-result v4

    sub-int v5, v4, v3

    rsub-int/lit8 v5, v5, 0xf

    sub-int/2addr v3, v5

    invoke-static {v0, v3}, Ljava/lang/Math;->max(II)I

    move-result v3

    const/4 v5, 0x0

    move v6, v3

    move-object v7, v5

    move v3, v0

    :goto_0
    if-ge v6, v4, :cond_3

    invoke-interface {p1, v6}, Landroid/widget/SpinnerAdapter;->getItemViewType(I)I

    move-result v8

    if-eq v8, v0, :cond_1

    move-object v7, v5

    move v0, v8

    :cond_1
    invoke-interface {p1, v6, v7, p0}, Landroid/widget/SpinnerAdapter;->getView(ILandroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;

    move-result-object v7

    invoke-virtual {v7}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v8

    if-nez v8, :cond_2

    new-instance v8, Landroid/view/ViewGroup$LayoutParams;

    const/4 v9, -0x2

    invoke-direct {v8, v9, v9}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    invoke-virtual {v7, v8}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    :cond_2
    invoke-virtual {v7, v1, v2}, Landroid/view/View;->measure(II)V

    invoke-virtual {v7}, Landroid/view/View;->getMeasuredWidth()I

    move-result v8

    invoke-static {v3, v8}, Ljava/lang/Math;->max(II)I

    move-result v3

    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    :cond_3
    if-eqz p2, :cond_4

    iget-object p1, p0, La/b/p/w;->i:Landroid/graphics/Rect;

    invoke-virtual {p2, p1}, Landroid/graphics/drawable/Drawable;->getPadding(Landroid/graphics/Rect;)Z

    iget-object p1, p0, La/b/p/w;->i:Landroid/graphics/Rect;

    iget p2, p1, Landroid/graphics/Rect;->left:I

    iget p1, p1, Landroid/graphics/Rect;->right:I

    add-int/2addr p2, p1

    add-int/2addr v3, p2

    :cond_4
    return v3
.end method

.method public b()V
    .locals 3

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    invoke-virtual {p0}, Landroid/widget/Spinner;->getTextDirection()I

    move-result v1

    invoke-virtual {p0}, Landroid/widget/Spinner;->getTextAlignment()I

    move-result v2

    invoke-interface {v0, v1, v2}, La/b/p/w$f;->f(II)V

    return-void
.end method

.method public drawableStateChanged()V
    .locals 1

    invoke-super {p0}, Landroid/widget/Spinner;->drawableStateChanged()V

    iget-object v0, p0, La/b/p/w;->b:La/b/p/e;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, La/b/p/e;->a()V

    :cond_0
    return-void
.end method

.method public getDropDownHorizontalOffset()I
    .locals 1

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz v0, :cond_0

    invoke-interface {v0}, La/b/p/w$f;->d()I

    move-result v0

    return v0

    :cond_0
    invoke-super {p0}, Landroid/widget/Spinner;->getDropDownHorizontalOffset()I

    move-result v0

    return v0
.end method

.method public getDropDownVerticalOffset()I
    .locals 1

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz v0, :cond_0

    invoke-interface {v0}, La/b/p/w$f;->j()I

    move-result v0

    return v0

    :cond_0
    invoke-super {p0}, Landroid/widget/Spinner;->getDropDownVerticalOffset()I

    move-result v0

    return v0
.end method

.method public getDropDownWidth()I
    .locals 1

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz v0, :cond_0

    iget v0, p0, La/b/p/w;->h:I

    return v0

    :cond_0
    invoke-super {p0}, Landroid/widget/Spinner;->getDropDownWidth()I

    move-result v0

    return v0
.end method

.method public final getInternalPopup()La/b/p/w$f;
    .locals 1

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    return-object v0
.end method

.method public getPopupBackground()Landroid/graphics/drawable/Drawable;
    .locals 1

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz v0, :cond_0

    invoke-interface {v0}, La/b/p/w$f;->n()Landroid/graphics/drawable/Drawable;

    move-result-object v0

    return-object v0

    :cond_0
    invoke-super {p0}, Landroid/widget/Spinner;->getPopupBackground()Landroid/graphics/drawable/Drawable;

    move-result-object v0

    return-object v0
.end method

.method public getPopupContext()Landroid/content/Context;
    .locals 1

    iget-object v0, p0, La/b/p/w;->c:Landroid/content/Context;

    return-object v0
.end method

.method public getPrompt()Ljava/lang/CharSequence;
    .locals 1

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz v0, :cond_0

    invoke-interface {v0}, La/b/p/w$f;->b()Ljava/lang/CharSequence;

    move-result-object v0

    goto :goto_0

    :cond_0
    invoke-super {p0}, Landroid/widget/Spinner;->getPrompt()Ljava/lang/CharSequence;

    move-result-object v0

    :goto_0
    return-object v0
.end method

.method public getSupportBackgroundTintList()Landroid/content/res/ColorStateList;
    .locals 1

    iget-object v0, p0, La/b/p/w;->b:La/b/p/e;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, La/b/p/e;->b()Landroid/content/res/ColorStateList;

    move-result-object v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return-object v0
.end method

.method public getSupportBackgroundTintMode()Landroid/graphics/PorterDuff$Mode;
    .locals 1

    iget-object v0, p0, La/b/p/w;->b:La/b/p/e;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, La/b/p/e;->c()Landroid/graphics/PorterDuff$Mode;

    move-result-object v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return-object v0
.end method

.method public onDetachedFromWindow()V
    .locals 1

    invoke-super {p0}, Landroid/widget/Spinner;->onDetachedFromWindow()V

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz v0, :cond_0

    invoke-interface {v0}, La/b/p/w$f;->a()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    invoke-interface {v0}, La/b/p/w$f;->dismiss()V

    :cond_0
    return-void
.end method

.method public onMeasure(II)V
    .locals 2

    invoke-super {p0, p1, p2}, Landroid/widget/Spinner;->onMeasure(II)V

    iget-object p2, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz p2, :cond_0

    invoke-static {p1}, Landroid/view/View$MeasureSpec;->getMode(I)I

    move-result p2

    const/high16 v0, -0x80000000

    if-ne p2, v0, :cond_0

    invoke-virtual {p0}, Landroid/widget/Spinner;->getMeasuredWidth()I

    move-result p2

    invoke-virtual {p0}, Landroid/widget/Spinner;->getAdapter()Landroid/widget/SpinnerAdapter;

    move-result-object v0

    invoke-virtual {p0}, Landroid/widget/Spinner;->getBackground()Landroid/graphics/drawable/Drawable;

    move-result-object v1

    invoke-virtual {p0, v0, v1}, La/b/p/w;->a(Landroid/widget/SpinnerAdapter;Landroid/graphics/drawable/Drawable;)I

    move-result v0

    invoke-static {p2, v0}, Ljava/lang/Math;->max(II)I

    move-result p2

    invoke-static {p1}, Landroid/view/View$MeasureSpec;->getSize(I)I

    move-result p1

    invoke-static {p2, p1}, Ljava/lang/Math;->min(II)I

    move-result p1

    invoke-virtual {p0}, Landroid/widget/Spinner;->getMeasuredHeight()I

    move-result p2

    invoke-virtual {p0, p1, p2}, Landroid/widget/Spinner;->setMeasuredDimension(II)V

    :cond_0
    return-void
.end method

.method public onRestoreInstanceState(Landroid/os/Parcelable;)V
    .locals 1

    check-cast p1, La/b/p/w$e;

    invoke-virtual {p1}, Landroid/view/View$BaseSavedState;->getSuperState()Landroid/os/Parcelable;

    move-result-object v0

    invoke-super {p0, v0}, Landroid/widget/Spinner;->onRestoreInstanceState(Landroid/os/Parcelable;)V

    iget-boolean p1, p1, La/b/p/w$e;->b:Z

    if-eqz p1, :cond_0

    invoke-virtual {p0}, Landroid/widget/Spinner;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    move-result-object p1

    if-eqz p1, :cond_0

    new-instance v0, La/b/p/w$a;

    invoke-direct {v0, p0}, La/b/p/w$a;-><init>(La/b/p/w;)V

    invoke-virtual {p1, v0}, Landroid/view/ViewTreeObserver;->addOnGlobalLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    :cond_0
    return-void
.end method

.method public onSaveInstanceState()Landroid/os/Parcelable;
    .locals 2

    new-instance v0, La/b/p/w$e;

    invoke-super {p0}, Landroid/widget/Spinner;->onSaveInstanceState()Landroid/os/Parcelable;

    move-result-object v1

    invoke-direct {v0, v1}, La/b/p/w$e;-><init>(Landroid/os/Parcelable;)V

    iget-object v1, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz v1, :cond_0

    invoke-interface {v1}, La/b/p/w$f;->a()Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v1, 0x1

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    iput-boolean v1, v0, La/b/p/w$e;->b:Z

    return-object v0
.end method

.method public onTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 1

    iget-object v0, p0, La/b/p/w;->d:La/b/p/h0;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p0, p1}, La/b/p/h0;->onTouch(Landroid/view/View;Landroid/view/MotionEvent;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    invoke-super {p0, p1}, Landroid/widget/Spinner;->onTouchEvent(Landroid/view/MotionEvent;)Z

    move-result p1

    return p1
.end method

.method public performClick()Z
    .locals 1

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz v0, :cond_1

    invoke-interface {v0}, La/b/p/w$f;->a()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p0}, La/b/p/w;->b()V

    :cond_0
    const/4 v0, 0x1

    return v0

    :cond_1
    invoke-super {p0}, Landroid/widget/Spinner;->performClick()Z

    move-result v0

    return v0
.end method

.method public bridge synthetic setAdapter(Landroid/widget/Adapter;)V
    .locals 0

    check-cast p1, Landroid/widget/SpinnerAdapter;

    invoke-virtual {p0, p1}, La/b/p/w;->setAdapter(Landroid/widget/SpinnerAdapter;)V

    return-void
.end method

.method public setAdapter(Landroid/widget/SpinnerAdapter;)V
    .locals 3

    iget-boolean v0, p0, La/b/p/w;->f:Z

    if-nez v0, :cond_0

    iput-object p1, p0, La/b/p/w;->e:Landroid/widget/SpinnerAdapter;

    return-void

    :cond_0
    invoke-super {p0, p1}, Landroid/widget/Spinner;->setAdapter(Landroid/widget/SpinnerAdapter;)V

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz v0, :cond_2

    iget-object v0, p0, La/b/p/w;->c:Landroid/content/Context;

    if-nez v0, :cond_1

    invoke-virtual {p0}, Landroid/widget/Spinner;->getContext()Landroid/content/Context;

    move-result-object v0

    :cond_1
    iget-object v1, p0, La/b/p/w;->g:La/b/p/w$f;

    new-instance v2, La/b/p/w$c;

    invoke-virtual {v0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v0

    invoke-direct {v2, p1, v0}, La/b/p/w$c;-><init>(Landroid/widget/SpinnerAdapter;Landroid/content/res/Resources$Theme;)V

    invoke-interface {v1, v2}, La/b/p/w$f;->o(Landroid/widget/ListAdapter;)V

    :cond_2
    return-void
.end method

.method public setBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V
    .locals 0

    invoke-super {p0, p1}, Landroid/widget/Spinner;->setBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V

    iget-object p1, p0, La/b/p/w;->b:La/b/p/e;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, La/b/p/e;->e()V

    :cond_0
    return-void
.end method

.method public setBackgroundResource(I)V
    .locals 1

    invoke-super {p0, p1}, Landroid/widget/Spinner;->setBackgroundResource(I)V

    iget-object v0, p0, La/b/p/w;->b:La/b/p/e;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, La/b/p/e;->f(I)V

    :cond_0
    return-void
.end method

.method public setDropDownHorizontalOffset(I)V
    .locals 1

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, La/b/p/w$f;->p(I)V

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    invoke-interface {v0, p1}, La/b/p/w$f;->c(I)V

    goto :goto_0

    :cond_0
    invoke-super {p0, p1}, Landroid/widget/Spinner;->setDropDownHorizontalOffset(I)V

    :goto_0
    return-void
.end method

.method public setDropDownVerticalOffset(I)V
    .locals 1

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, La/b/p/w$f;->m(I)V

    goto :goto_0

    :cond_0
    invoke-super {p0, p1}, Landroid/widget/Spinner;->setDropDownVerticalOffset(I)V

    :goto_0
    return-void
.end method

.method public setDropDownWidth(I)V
    .locals 1

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz v0, :cond_0

    iput p1, p0, La/b/p/w;->h:I

    goto :goto_0

    :cond_0
    invoke-super {p0, p1}, Landroid/widget/Spinner;->setDropDownWidth(I)V

    :goto_0
    return-void
.end method

.method public setPopupBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V
    .locals 1

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, La/b/p/w$f;->l(Landroid/graphics/drawable/Drawable;)V

    goto :goto_0

    :cond_0
    invoke-super {p0, p1}, Landroid/widget/Spinner;->setPopupBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V

    :goto_0
    return-void
.end method

.method public setPopupBackgroundResource(I)V
    .locals 1

    invoke-virtual {p0}, La/b/p/w;->getPopupContext()Landroid/content/Context;

    move-result-object v0

    invoke-static {v0, p1}, La/b/l/a/a;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    move-result-object p1

    invoke-virtual {p0, p1}, La/b/p/w;->setPopupBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V

    return-void
.end method

.method public setPrompt(Ljava/lang/CharSequence;)V
    .locals 1

    iget-object v0, p0, La/b/p/w;->g:La/b/p/w$f;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, La/b/p/w$f;->h(Ljava/lang/CharSequence;)V

    goto :goto_0

    :cond_0
    invoke-super {p0, p1}, Landroid/widget/Spinner;->setPrompt(Ljava/lang/CharSequence;)V

    :goto_0
    return-void
.end method

.method public setSupportBackgroundTintList(Landroid/content/res/ColorStateList;)V
    .locals 1

    iget-object v0, p0, La/b/p/w;->b:La/b/p/e;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, La/b/p/e;->h(Landroid/content/res/ColorStateList;)V

    :cond_0
    return-void
.end method

.method public setSupportBackgroundTintMode(Landroid/graphics/PorterDuff$Mode;)V
    .locals 1

    iget-object v0, p0, La/b/p/w;->b:La/b/p/e;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, La/b/p/e;->i(Landroid/graphics/PorterDuff$Mode;)V

    :cond_0
    return-void
.end method
