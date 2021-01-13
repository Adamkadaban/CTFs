.class public La/b/p/y;
.super Ljava/lang/Object;
.source ""


# instance fields
.field public final a:Landroid/widget/TextView;

.field public b:La/b/p/v0;

.field public c:La/b/p/v0;

.field public d:La/b/p/v0;

.field public e:La/b/p/v0;

.field public f:La/b/p/v0;

.field public g:La/b/p/v0;

.field public h:La/b/p/v0;

.field public final i:La/b/p/a0;

.field public j:I

.field public k:I

.field public l:Landroid/graphics/Typeface;

.field public m:Z


# direct methods
.method public constructor <init>(Landroid/widget/TextView;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput v0, p0, La/b/p/y;->j:I

    const/4 v0, -0x1

    iput v0, p0, La/b/p/y;->k:I

    iput-object p1, p0, La/b/p/y;->a:Landroid/widget/TextView;

    new-instance p1, La/b/p/a0;

    iget-object v0, p0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-direct {p1, v0}, La/b/p/a0;-><init>(Landroid/widget/TextView;)V

    iput-object p1, p0, La/b/p/y;->i:La/b/p/a0;

    return-void
.end method

.method public static c(Landroid/content/Context;La/b/p/j;I)La/b/p/v0;
    .locals 0

    invoke-virtual {p1, p0, p2}, La/b/p/j;->c(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    move-result-object p0

    if-eqz p0, :cond_0

    new-instance p1, La/b/p/v0;

    invoke-direct {p1}, La/b/p/v0;-><init>()V

    const/4 p2, 0x1

    iput-boolean p2, p1, La/b/p/v0;->d:Z

    iput-object p0, p1, La/b/p/v0;->a:Landroid/content/res/ColorStateList;

    return-object p1

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method


# virtual methods
.method public final a(Landroid/graphics/drawable/Drawable;La/b/p/v0;)V
    .locals 1

    if-eqz p1, :cond_0

    if-eqz p2, :cond_0

    iget-object v0, p0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v0}, Landroid/widget/TextView;->getDrawableState()[I

    move-result-object v0

    invoke-static {p1, p2, v0}, La/b/p/j;->e(Landroid/graphics/drawable/Drawable;La/b/p/v0;[I)V

    :cond_0
    return-void
.end method

.method public b()V
    .locals 5

    iget-object v0, p0, La/b/p/y;->b:La/b/p/v0;

    const/4 v1, 0x2

    const/4 v2, 0x0

    if-nez v0, :cond_0

    iget-object v0, p0, La/b/p/y;->c:La/b/p/v0;

    if-nez v0, :cond_0

    iget-object v0, p0, La/b/p/y;->d:La/b/p/v0;

    if-nez v0, :cond_0

    iget-object v0, p0, La/b/p/y;->e:La/b/p/v0;

    if-eqz v0, :cond_1

    :cond_0
    iget-object v0, p0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v0}, Landroid/widget/TextView;->getCompoundDrawables()[Landroid/graphics/drawable/Drawable;

    move-result-object v0

    aget-object v3, v0, v2

    iget-object v4, p0, La/b/p/y;->b:La/b/p/v0;

    invoke-virtual {p0, v3, v4}, La/b/p/y;->a(Landroid/graphics/drawable/Drawable;La/b/p/v0;)V

    const/4 v3, 0x1

    aget-object v3, v0, v3

    iget-object v4, p0, La/b/p/y;->c:La/b/p/v0;

    invoke-virtual {p0, v3, v4}, La/b/p/y;->a(Landroid/graphics/drawable/Drawable;La/b/p/v0;)V

    aget-object v3, v0, v1

    iget-object v4, p0, La/b/p/y;->d:La/b/p/v0;

    invoke-virtual {p0, v3, v4}, La/b/p/y;->a(Landroid/graphics/drawable/Drawable;La/b/p/v0;)V

    const/4 v3, 0x3

    aget-object v0, v0, v3

    iget-object v3, p0, La/b/p/y;->e:La/b/p/v0;

    invoke-virtual {p0, v0, v3}, La/b/p/y;->a(Landroid/graphics/drawable/Drawable;La/b/p/v0;)V

    :cond_1
    iget-object v0, p0, La/b/p/y;->f:La/b/p/v0;

    if-nez v0, :cond_2

    iget-object v0, p0, La/b/p/y;->g:La/b/p/v0;

    if-eqz v0, :cond_3

    :cond_2
    iget-object v0, p0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v0}, Landroid/widget/TextView;->getCompoundDrawablesRelative()[Landroid/graphics/drawable/Drawable;

    move-result-object v0

    aget-object v2, v0, v2

    iget-object v3, p0, La/b/p/y;->f:La/b/p/v0;

    invoke-virtual {p0, v2, v3}, La/b/p/y;->a(Landroid/graphics/drawable/Drawable;La/b/p/v0;)V

    aget-object v0, v0, v1

    iget-object v1, p0, La/b/p/y;->g:La/b/p/v0;

    invoke-virtual {p0, v0, v1}, La/b/p/y;->a(Landroid/graphics/drawable/Drawable;La/b/p/v0;)V

    :cond_3
    return-void
.end method

.method public d()Z
    .locals 2

    iget-object v0, p0, La/b/p/y;->i:La/b/p/a0;

    .line 1
    invoke-virtual {v0}, La/b/p/a0;->i()Z

    move-result v1

    if-eqz v1, :cond_0

    iget v0, v0, La/b/p/a0;->a:I

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public e(Landroid/util/AttributeSet;I)V
    .locals 18
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "NewApi"
        }
    .end annotation

    move-object/from16 v0, p0

    move-object/from16 v8, p1

    move/from16 v9, p2

    iget-object v1, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v1}, Landroid/widget/TextView;->getContext()Landroid/content/Context;

    move-result-object v10

    invoke-static {}, La/b/p/j;->a()La/b/p/j;

    move-result-object v11

    sget-object v1, La/b/j;->AppCompatTextHelper:[I

    const/4 v12, 0x0

    invoke-static {v10, v8, v1, v9, v12}, La/b/p/x0;->o(Landroid/content/Context;Landroid/util/AttributeSet;[III)La/b/p/x0;

    move-result-object v13

    iget-object v1, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v1}, Landroid/widget/TextView;->getContext()Landroid/content/Context;

    move-result-object v2

    sget-object v3, La/b/j;->AppCompatTextHelper:[I

    .line 1
    iget-object v5, v13, La/b/p/x0;->b:Landroid/content/res/TypedArray;

    const/4 v7, 0x0

    move-object/from16 v4, p1

    move/from16 v6, p2

    .line 2
    invoke-static/range {v1 .. v7}, La/f/j/k;->t(Landroid/view/View;Landroid/content/Context;[ILandroid/util/AttributeSet;Landroid/content/res/TypedArray;II)V

    sget v1, La/b/j;->AppCompatTextHelper_android_textAppearance:I

    const/4 v14, -0x1

    invoke-virtual {v13, v1, v14}, La/b/p/x0;->j(II)I

    move-result v1

    sget v2, La/b/j;->AppCompatTextHelper_android_drawableLeft:I

    invoke-virtual {v13, v2}, La/b/p/x0;->m(I)Z

    move-result v2

    if-eqz v2, :cond_0

    sget v2, La/b/j;->AppCompatTextHelper_android_drawableLeft:I

    invoke-virtual {v13, v2, v12}, La/b/p/x0;->j(II)I

    move-result v2

    invoke-static {v10, v11, v2}, La/b/p/y;->c(Landroid/content/Context;La/b/p/j;I)La/b/p/v0;

    move-result-object v2

    iput-object v2, v0, La/b/p/y;->b:La/b/p/v0;

    :cond_0
    sget v2, La/b/j;->AppCompatTextHelper_android_drawableTop:I

    invoke-virtual {v13, v2}, La/b/p/x0;->m(I)Z

    move-result v2

    if-eqz v2, :cond_1

    sget v2, La/b/j;->AppCompatTextHelper_android_drawableTop:I

    invoke-virtual {v13, v2, v12}, La/b/p/x0;->j(II)I

    move-result v2

    invoke-static {v10, v11, v2}, La/b/p/y;->c(Landroid/content/Context;La/b/p/j;I)La/b/p/v0;

    move-result-object v2

    iput-object v2, v0, La/b/p/y;->c:La/b/p/v0;

    :cond_1
    sget v2, La/b/j;->AppCompatTextHelper_android_drawableRight:I

    invoke-virtual {v13, v2}, La/b/p/x0;->m(I)Z

    move-result v2

    if-eqz v2, :cond_2

    sget v2, La/b/j;->AppCompatTextHelper_android_drawableRight:I

    invoke-virtual {v13, v2, v12}, La/b/p/x0;->j(II)I

    move-result v2

    invoke-static {v10, v11, v2}, La/b/p/y;->c(Landroid/content/Context;La/b/p/j;I)La/b/p/v0;

    move-result-object v2

    iput-object v2, v0, La/b/p/y;->d:La/b/p/v0;

    :cond_2
    sget v2, La/b/j;->AppCompatTextHelper_android_drawableBottom:I

    invoke-virtual {v13, v2}, La/b/p/x0;->m(I)Z

    move-result v2

    if-eqz v2, :cond_3

    sget v2, La/b/j;->AppCompatTextHelper_android_drawableBottom:I

    invoke-virtual {v13, v2, v12}, La/b/p/x0;->j(II)I

    move-result v2

    invoke-static {v10, v11, v2}, La/b/p/y;->c(Landroid/content/Context;La/b/p/j;I)La/b/p/v0;

    move-result-object v2

    iput-object v2, v0, La/b/p/y;->e:La/b/p/v0;

    :cond_3
    sget v2, La/b/j;->AppCompatTextHelper_android_drawableStart:I

    invoke-virtual {v13, v2}, La/b/p/x0;->m(I)Z

    move-result v2

    if-eqz v2, :cond_4

    sget v2, La/b/j;->AppCompatTextHelper_android_drawableStart:I

    invoke-virtual {v13, v2, v12}, La/b/p/x0;->j(II)I

    move-result v2

    invoke-static {v10, v11, v2}, La/b/p/y;->c(Landroid/content/Context;La/b/p/j;I)La/b/p/v0;

    move-result-object v2

    iput-object v2, v0, La/b/p/y;->f:La/b/p/v0;

    :cond_4
    sget v2, La/b/j;->AppCompatTextHelper_android_drawableEnd:I

    invoke-virtual {v13, v2}, La/b/p/x0;->m(I)Z

    move-result v2

    if-eqz v2, :cond_5

    sget v2, La/b/j;->AppCompatTextHelper_android_drawableEnd:I

    invoke-virtual {v13, v2, v12}, La/b/p/x0;->j(II)I

    move-result v2

    invoke-static {v10, v11, v2}, La/b/p/y;->c(Landroid/content/Context;La/b/p/j;I)La/b/p/v0;

    move-result-object v2

    iput-object v2, v0, La/b/p/y;->g:La/b/p/v0;

    .line 3
    :cond_5
    iget-object v2, v13, La/b/p/x0;->b:Landroid/content/res/TypedArray;

    invoke-virtual {v2}, Landroid/content/res/TypedArray;->recycle()V

    .line 4
    iget-object v2, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v2}, Landroid/widget/TextView;->getTransformationMethod()Landroid/text/method/TransformationMethod;

    move-result-object v2

    instance-of v2, v2, Landroid/text/method/PasswordTransformationMethod;

    const/16 v3, 0x1a

    const/4 v13, 0x1

    if-eq v1, v14, :cond_9

    sget-object v4, La/b/j;->TextAppearance:[I

    .line 5
    new-instance v5, La/b/p/x0;

    invoke-virtual {v10, v1, v4}, Landroid/content/Context;->obtainStyledAttributes(I[I)Landroid/content/res/TypedArray;

    move-result-object v1

    invoke-direct {v5, v10, v1}, La/b/p/x0;-><init>(Landroid/content/Context;Landroid/content/res/TypedArray;)V

    if-nez v2, :cond_6

    .line 6
    sget v1, La/b/j;->TextAppearance_textAllCaps:I

    invoke-virtual {v5, v1}, La/b/p/x0;->m(I)Z

    move-result v1

    if-eqz v1, :cond_6

    sget v1, La/b/j;->TextAppearance_textAllCaps:I

    invoke-virtual {v5, v1, v12}, La/b/p/x0;->a(IZ)Z

    move-result v1

    move v4, v13

    goto :goto_0

    :cond_6
    move v1, v12

    move v4, v1

    :goto_0
    invoke-virtual {v0, v10, v5}, La/b/p/y;->l(Landroid/content/Context;La/b/p/x0;)V

    sget v6, La/b/j;->TextAppearance_textLocale:I

    invoke-virtual {v5, v6}, La/b/p/x0;->m(I)Z

    move-result v6

    if-eqz v6, :cond_7

    sget v6, La/b/j;->TextAppearance_textLocale:I

    invoke-virtual {v5, v6}, La/b/p/x0;->k(I)Ljava/lang/String;

    move-result-object v6

    goto :goto_1

    :cond_7
    const/4 v6, 0x0

    :goto_1
    sget v7, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v7, v3, :cond_8

    sget v7, La/b/j;->TextAppearance_fontVariationSettings:I

    invoke-virtual {v5, v7}, La/b/p/x0;->m(I)Z

    move-result v7

    if-eqz v7, :cond_8

    sget v7, La/b/j;->TextAppearance_fontVariationSettings:I

    invoke-virtual {v5, v7}, La/b/p/x0;->k(I)Ljava/lang/String;

    move-result-object v7

    goto :goto_2

    :cond_8
    const/4 v7, 0x0

    .line 7
    :goto_2
    iget-object v5, v5, La/b/p/x0;->b:Landroid/content/res/TypedArray;

    invoke-virtual {v5}, Landroid/content/res/TypedArray;->recycle()V

    goto :goto_3

    :cond_9
    move v1, v12

    move v4, v1

    const/4 v6, 0x0

    const/4 v7, 0x0

    .line 8
    :goto_3
    sget-object v5, La/b/j;->TextAppearance:[I

    .line 9
    new-instance v15, La/b/p/x0;

    invoke-virtual {v10, v8, v5, v9, v12}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    move-result-object v5

    invoke-direct {v15, v10, v5}, La/b/p/x0;-><init>(Landroid/content/Context;Landroid/content/res/TypedArray;)V

    if-nez v2, :cond_a

    .line 10
    sget v5, La/b/j;->TextAppearance_textAllCaps:I

    invoke-virtual {v15, v5}, La/b/p/x0;->m(I)Z

    move-result v5

    if-eqz v5, :cond_a

    sget v1, La/b/j;->TextAppearance_textAllCaps:I

    invoke-virtual {v15, v1, v12}, La/b/p/x0;->a(IZ)Z

    move-result v1

    move v4, v13

    :cond_a
    sget v5, La/b/j;->TextAppearance_textLocale:I

    invoke-virtual {v15, v5}, La/b/p/x0;->m(I)Z

    move-result v5

    if-eqz v5, :cond_b

    sget v5, La/b/j;->TextAppearance_textLocale:I

    invoke-virtual {v15, v5}, La/b/p/x0;->k(I)Ljava/lang/String;

    move-result-object v6

    :cond_b
    sget v5, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v5, v3, :cond_c

    sget v3, La/b/j;->TextAppearance_fontVariationSettings:I

    invoke-virtual {v15, v3}, La/b/p/x0;->m(I)Z

    move-result v3

    if-eqz v3, :cond_c

    sget v3, La/b/j;->TextAppearance_fontVariationSettings:I

    invoke-virtual {v15, v3}, La/b/p/x0;->k(I)Ljava/lang/String;

    move-result-object v7

    :cond_c
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v5, 0x1c

    if-lt v3, v5, :cond_d

    sget v3, La/b/j;->TextAppearance_android_textSize:I

    invoke-virtual {v15, v3}, La/b/p/x0;->m(I)Z

    move-result v3

    if-eqz v3, :cond_d

    sget v3, La/b/j;->TextAppearance_android_textSize:I

    invoke-virtual {v15, v3, v14}, La/b/p/x0;->d(II)I

    move-result v3

    if-nez v3, :cond_d

    iget-object v3, v0, La/b/p/y;->a:Landroid/widget/TextView;

    const/4 v5, 0x0

    invoke-virtual {v3, v12, v5}, Landroid/widget/TextView;->setTextSize(IF)V

    :cond_d
    invoke-virtual {v0, v10, v15}, La/b/p/y;->l(Landroid/content/Context;La/b/p/x0;)V

    .line 11
    iget-object v3, v15, La/b/p/x0;->b:Landroid/content/res/TypedArray;

    invoke-virtual {v3}, Landroid/content/res/TypedArray;->recycle()V

    if-nez v2, :cond_e

    if-eqz v4, :cond_e

    .line 12
    iget-object v2, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v2, v1}, Landroid/widget/TextView;->setAllCaps(Z)V

    .line 13
    :cond_e
    iget-object v1, v0, La/b/p/y;->l:Landroid/graphics/Typeface;

    if-eqz v1, :cond_10

    iget v2, v0, La/b/p/y;->k:I

    if-ne v2, v14, :cond_f

    iget-object v2, v0, La/b/p/y;->a:Landroid/widget/TextView;

    iget v3, v0, La/b/p/y;->j:I

    invoke-virtual {v2, v1, v3}, Landroid/widget/TextView;->setTypeface(Landroid/graphics/Typeface;I)V

    goto :goto_4

    :cond_f
    iget-object v2, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v2, v1}, Landroid/widget/TextView;->setTypeface(Landroid/graphics/Typeface;)V

    :cond_10
    :goto_4
    if-eqz v7, :cond_11

    iget-object v1, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v1, v7}, Landroid/widget/TextView;->setFontVariationSettings(Ljava/lang/String;)Z

    :cond_11
    if-eqz v6, :cond_12

    iget-object v1, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-static {v6}, Landroid/os/LocaleList;->forLanguageTags(Ljava/lang/String;)Landroid/os/LocaleList;

    move-result-object v2

    invoke-virtual {v1, v2}, Landroid/widget/TextView;->setTextLocales(Landroid/os/LocaleList;)V

    :cond_12
    iget-object v15, v0, La/b/p/y;->i:La/b/p/a0;

    .line 14
    iget-object v1, v15, La/b/p/a0;->j:Landroid/content/Context;

    sget-object v2, La/b/j;->AppCompatTextView:[I

    invoke-virtual {v1, v8, v2, v9, v12}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    move-result-object v7

    iget-object v1, v15, La/b/p/a0;->i:Landroid/widget/TextView;

    invoke-virtual {v1}, Landroid/widget/TextView;->getContext()Landroid/content/Context;

    move-result-object v2

    sget-object v3, La/b/j;->AppCompatTextView:[I

    const/16 v16, 0x0

    move-object/from16 v4, p1

    move-object v5, v7

    move/from16 v6, p2

    move-object v9, v7

    move/from16 v7, v16

    invoke-static/range {v1 .. v7}, La/f/j/k;->t(Landroid/view/View;Landroid/content/Context;[ILandroid/util/AttributeSet;Landroid/content/res/TypedArray;II)V

    sget v1, La/b/j;->AppCompatTextView_autoSizeTextType:I

    invoke-virtual {v9, v1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v1

    if-eqz v1, :cond_13

    sget v1, La/b/j;->AppCompatTextView_autoSizeTextType:I

    invoke-virtual {v9, v1, v12}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v1

    iput v1, v15, La/b/p/a0;->a:I

    :cond_13
    sget v1, La/b/j;->AppCompatTextView_autoSizeStepGranularity:I

    invoke-virtual {v9, v1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v1

    const/high16 v2, -0x40800000    # -1.0f

    if-eqz v1, :cond_14

    sget v1, La/b/j;->AppCompatTextView_autoSizeStepGranularity:I

    invoke-virtual {v9, v1, v2}, Landroid/content/res/TypedArray;->getDimension(IF)F

    move-result v1

    goto :goto_5

    :cond_14
    move v1, v2

    :goto_5
    sget v3, La/b/j;->AppCompatTextView_autoSizeMinTextSize:I

    invoke-virtual {v9, v3}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v3

    if-eqz v3, :cond_15

    sget v3, La/b/j;->AppCompatTextView_autoSizeMinTextSize:I

    invoke-virtual {v9, v3, v2}, Landroid/content/res/TypedArray;->getDimension(IF)F

    move-result v3

    goto :goto_6

    :cond_15
    move v3, v2

    :goto_6
    sget v4, La/b/j;->AppCompatTextView_autoSizeMaxTextSize:I

    invoke-virtual {v9, v4}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v4

    if-eqz v4, :cond_16

    sget v4, La/b/j;->AppCompatTextView_autoSizeMaxTextSize:I

    invoke-virtual {v9, v4, v2}, Landroid/content/res/TypedArray;->getDimension(IF)F

    move-result v4

    goto :goto_7

    :cond_16
    move v4, v2

    :goto_7
    sget v5, La/b/j;->AppCompatTextView_autoSizePresetSizes:I

    invoke-virtual {v9, v5}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v5

    if-eqz v5, :cond_19

    sget v5, La/b/j;->AppCompatTextView_autoSizePresetSizes:I

    invoke-virtual {v9, v5, v12}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v5

    if-lez v5, :cond_19

    invoke-virtual {v9}, Landroid/content/res/TypedArray;->getResources()Landroid/content/res/Resources;

    move-result-object v6

    invoke-virtual {v6, v5}, Landroid/content/res/Resources;->obtainTypedArray(I)Landroid/content/res/TypedArray;

    move-result-object v5

    .line 15
    invoke-virtual {v5}, Landroid/content/res/TypedArray;->length()I

    move-result v6

    new-array v7, v6, [I

    if-lez v6, :cond_18

    :goto_8
    if-ge v12, v6, :cond_17

    invoke-virtual {v5, v12, v14}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v17

    aput v17, v7, v12

    add-int/lit8 v12, v12, 0x1

    goto :goto_8

    :cond_17
    invoke-virtual {v15, v7}, La/b/p/a0;->b([I)[I

    move-result-object v6

    iput-object v6, v15, La/b/p/a0;->f:[I

    invoke-virtual {v15}, La/b/p/a0;->h()Z

    .line 16
    :cond_18
    invoke-virtual {v5}, Landroid/content/res/TypedArray;->recycle()V

    :cond_19
    invoke-virtual {v9}, Landroid/content/res/TypedArray;->recycle()V

    invoke-virtual {v15}, La/b/p/a0;->i()Z

    move-result v5

    const/4 v6, 0x2

    if-eqz v5, :cond_1e

    iget v5, v15, La/b/p/a0;->a:I

    if-ne v5, v13, :cond_1f

    iget-boolean v5, v15, La/b/p/a0;->g:Z

    if-nez v5, :cond_1d

    iget-object v5, v15, La/b/p/a0;->j:Landroid/content/Context;

    invoke-virtual {v5}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v5

    invoke-virtual {v5}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v5

    cmpl-float v7, v3, v2

    if-nez v7, :cond_1a

    const/high16 v3, 0x41400000    # 12.0f

    invoke-static {v6, v3, v5}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    move-result v3

    :cond_1a
    cmpl-float v7, v4, v2

    if-nez v7, :cond_1b

    const/high16 v4, 0x42e00000    # 112.0f

    invoke-static {v6, v4, v5}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    move-result v4

    :cond_1b
    cmpl-float v5, v1, v2

    if-nez v5, :cond_1c

    const/high16 v1, 0x3f800000    # 1.0f

    :cond_1c
    invoke-virtual {v15, v3, v4, v1}, La/b/p/a0;->j(FFF)V

    :cond_1d
    invoke-virtual {v15}, La/b/p/a0;->g()Z

    goto :goto_9

    :cond_1e
    const/4 v1, 0x0

    iput v1, v15, La/b/p/a0;->a:I

    .line 17
    :cond_1f
    :goto_9
    sget-boolean v1, La/f/k/b;->a:Z

    if-eqz v1, :cond_21

    iget-object v1, v0, La/b/p/y;->i:La/b/p/a0;

    .line 18
    iget v3, v1, La/b/p/a0;->a:I

    if-eqz v3, :cond_21

    .line 19
    iget-object v1, v1, La/b/p/a0;->f:[I

    .line 20
    array-length v3, v1

    if-lez v3, :cond_21

    iget-object v3, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v3}, Landroid/widget/TextView;->getAutoSizeStepGranularity()I

    move-result v3

    int-to-float v3, v3

    cmpl-float v2, v3, v2

    if-eqz v2, :cond_20

    iget-object v1, v0, La/b/p/y;->a:Landroid/widget/TextView;

    iget-object v2, v0, La/b/p/y;->i:La/b/p/a0;

    .line 21
    iget v2, v2, La/b/p/a0;->d:F

    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    move-result v2

    .line 22
    iget-object v3, v0, La/b/p/y;->i:La/b/p/a0;

    .line 23
    iget v3, v3, La/b/p/a0;->e:F

    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    move-result v3

    .line 24
    iget-object v4, v0, La/b/p/y;->i:La/b/p/a0;

    .line 25
    iget v4, v4, La/b/p/a0;->c:F

    invoke-static {v4}, Ljava/lang/Math;->round(F)I

    move-result v4

    const/4 v5, 0x0

    .line 26
    invoke-virtual {v1, v2, v3, v4, v5}, Landroid/widget/TextView;->setAutoSizeTextTypeUniformWithConfiguration(IIII)V

    goto :goto_a

    :cond_20
    const/4 v5, 0x0

    iget-object v2, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v2, v1, v5}, Landroid/widget/TextView;->setAutoSizeTextTypeUniformWithPresetSizes([II)V

    :cond_21
    :goto_a
    sget-object v1, La/b/j;->AppCompatTextView:[I

    .line 27
    invoke-virtual {v10, v8, v1}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object v1

    .line 28
    sget v2, La/b/j;->AppCompatTextView_drawableLeftCompat:I

    .line 29
    invoke-virtual {v1, v2, v14}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v2

    if-eq v2, v14, :cond_22

    .line 30
    invoke-virtual {v11, v10, v2}, La/b/p/j;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    move-result-object v2

    goto :goto_b

    :cond_22
    const/4 v2, 0x0

    :goto_b
    sget v3, La/b/j;->AppCompatTextView_drawableTopCompat:I

    .line 31
    invoke-virtual {v1, v3, v14}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v3

    if-eq v3, v14, :cond_23

    .line 32
    invoke-virtual {v11, v10, v3}, La/b/p/j;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    move-result-object v3

    goto :goto_c

    :cond_23
    const/4 v3, 0x0

    :goto_c
    sget v4, La/b/j;->AppCompatTextView_drawableRightCompat:I

    .line 33
    invoke-virtual {v1, v4, v14}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    if-eq v4, v14, :cond_24

    .line 34
    invoke-virtual {v11, v10, v4}, La/b/p/j;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    move-result-object v4

    goto :goto_d

    :cond_24
    const/4 v4, 0x0

    :goto_d
    sget v5, La/b/j;->AppCompatTextView_drawableBottomCompat:I

    .line 35
    invoke-virtual {v1, v5, v14}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v5

    if-eq v5, v14, :cond_25

    .line 36
    invoke-virtual {v11, v10, v5}, La/b/p/j;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    move-result-object v5

    goto :goto_e

    :cond_25
    const/4 v5, 0x0

    :goto_e
    sget v7, La/b/j;->AppCompatTextView_drawableStartCompat:I

    .line 37
    invoke-virtual {v1, v7, v14}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    if-eq v7, v14, :cond_26

    .line 38
    invoke-virtual {v11, v10, v7}, La/b/p/j;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    move-result-object v7

    goto :goto_f

    :cond_26
    const/4 v7, 0x0

    :goto_f
    sget v8, La/b/j;->AppCompatTextView_drawableEndCompat:I

    .line 39
    invoke-virtual {v1, v8, v14}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v8

    if-eq v8, v14, :cond_27

    .line 40
    invoke-virtual {v11, v10, v8}, La/b/p/j;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    move-result-object v8

    goto :goto_10

    :cond_27
    const/4 v8, 0x0

    :goto_10
    const/4 v9, 0x3

    if-nez v7, :cond_32

    if-eqz v8, :cond_28

    goto :goto_18

    :cond_28
    if-nez v2, :cond_29

    if-nez v3, :cond_29

    if-nez v4, :cond_29

    if-eqz v5, :cond_37

    .line 41
    :cond_29
    iget-object v7, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v7}, Landroid/widget/TextView;->getCompoundDrawablesRelative()[Landroid/graphics/drawable/Drawable;

    move-result-object v7

    const/4 v8, 0x0

    aget-object v11, v7, v8

    if-nez v11, :cond_2f

    aget-object v11, v7, v6

    if-eqz v11, :cond_2a

    goto :goto_15

    :cond_2a
    iget-object v7, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v7}, Landroid/widget/TextView;->getCompoundDrawables()[Landroid/graphics/drawable/Drawable;

    move-result-object v7

    iget-object v11, v0, La/b/p/y;->a:Landroid/widget/TextView;

    if-eqz v2, :cond_2b

    goto :goto_11

    :cond_2b
    aget-object v2, v7, v8

    :goto_11
    if-eqz v3, :cond_2c

    goto :goto_12

    :cond_2c
    aget-object v3, v7, v13

    :goto_12
    if-eqz v4, :cond_2d

    goto :goto_13

    :cond_2d
    aget-object v4, v7, v6

    :goto_13
    if-eqz v5, :cond_2e

    goto :goto_14

    :cond_2e
    aget-object v5, v7, v9

    :goto_14
    invoke-virtual {v11, v2, v3, v4, v5}, Landroid/widget/TextView;->setCompoundDrawablesWithIntrinsicBounds(Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;)V

    goto :goto_1d

    :cond_2f
    :goto_15
    iget-object v2, v0, La/b/p/y;->a:Landroid/widget/TextView;

    const/4 v4, 0x0

    aget-object v8, v7, v4

    if-eqz v3, :cond_30

    goto :goto_16

    :cond_30
    aget-object v3, v7, v13

    :goto_16
    aget-object v4, v7, v6

    if-eqz v5, :cond_31

    goto :goto_17

    :cond_31
    aget-object v5, v7, v9

    :goto_17
    invoke-virtual {v2, v8, v3, v4, v5}, Landroid/widget/TextView;->setCompoundDrawablesRelativeWithIntrinsicBounds(Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;)V

    goto :goto_1d

    :cond_32
    :goto_18
    iget-object v2, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v2}, Landroid/widget/TextView;->getCompoundDrawablesRelative()[Landroid/graphics/drawable/Drawable;

    move-result-object v2

    iget-object v4, v0, La/b/p/y;->a:Landroid/widget/TextView;

    if-eqz v7, :cond_33

    goto :goto_19

    :cond_33
    const/4 v7, 0x0

    aget-object v11, v2, v7

    move-object v7, v11

    :goto_19
    if-eqz v3, :cond_34

    goto :goto_1a

    :cond_34
    aget-object v3, v2, v13

    :goto_1a
    if-eqz v8, :cond_35

    goto :goto_1b

    :cond_35
    aget-object v8, v2, v6

    :goto_1b
    if-eqz v5, :cond_36

    goto :goto_1c

    :cond_36
    aget-object v5, v2, v9

    :goto_1c
    invoke-virtual {v4, v7, v3, v8, v5}, Landroid/widget/TextView;->setCompoundDrawablesRelativeWithIntrinsicBounds(Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;)V

    .line 42
    :cond_37
    :goto_1d
    sget v2, La/b/j;->AppCompatTextView_drawableTint:I

    .line 43
    invoke-virtual {v1, v2}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v2

    if-eqz v2, :cond_3a

    .line 44
    sget v2, La/b/j;->AppCompatTextView_drawableTint:I

    .line 45
    invoke-virtual {v1, v2}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v3

    if-eqz v3, :cond_38

    const/4 v3, 0x0

    invoke-virtual {v1, v2, v3}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v3

    if-eqz v3, :cond_38

    invoke-static {v10, v3}, La/b/l/a/a;->a(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    move-result-object v3

    if-eqz v3, :cond_38

    goto :goto_1e

    :cond_38
    invoke-virtual {v1, v2}, Landroid/content/res/TypedArray;->getColorStateList(I)Landroid/content/res/ColorStateList;

    move-result-object v3

    .line 46
    :goto_1e
    iget-object v2, v0, La/b/p/y;->a:Landroid/widget/TextView;

    if-eqz v2, :cond_39

    .line 47
    invoke-virtual {v2, v3}, Landroid/widget/TextView;->setCompoundDrawableTintList(Landroid/content/res/ColorStateList;)V

    goto :goto_1f

    :cond_39
    const/4 v2, 0x0

    .line 48
    throw v2

    :cond_3a
    :goto_1f
    const/4 v2, 0x0

    .line 49
    sget v3, La/b/j;->AppCompatTextView_drawableTintMode:I

    .line 50
    invoke-virtual {v1, v3}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v3

    if-eqz v3, :cond_3c

    .line 51
    sget v3, La/b/j;->AppCompatTextView_drawableTintMode:I

    .line 52
    invoke-virtual {v1, v3, v14}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v3

    .line 53
    invoke-static {v3, v2}, La/b/p/e0;->c(ILandroid/graphics/PorterDuff$Mode;)Landroid/graphics/PorterDuff$Mode;

    move-result-object v3

    iget-object v4, v0, La/b/p/y;->a:Landroid/widget/TextView;

    if-eqz v4, :cond_3b

    .line 54
    invoke-virtual {v4, v3}, Landroid/widget/TextView;->setCompoundDrawableTintMode(Landroid/graphics/PorterDuff$Mode;)V

    goto :goto_20

    .line 55
    :cond_3b
    throw v2

    .line 56
    :cond_3c
    :goto_20
    sget v2, La/b/j;->AppCompatTextView_firstBaselineToTopHeight:I

    .line 57
    invoke-virtual {v1, v2, v14}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v2

    .line 58
    sget v3, La/b/j;->AppCompatTextView_lastBaselineToBottomHeight:I

    .line 59
    invoke-virtual {v1, v3, v14}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v3

    .line 60
    sget v4, La/b/j;->AppCompatTextView_lineHeight:I

    .line 61
    invoke-virtual {v1, v4, v14}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v4

    .line 62
    invoke-virtual {v1}, Landroid/content/res/TypedArray;->recycle()V

    if-eq v2, v14, :cond_3d

    .line 63
    iget-object v1, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-static {v1, v2}, La/b/k/h$i;->x(Landroid/widget/TextView;I)V

    :cond_3d
    if-eq v3, v14, :cond_3e

    iget-object v1, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-static {v1, v3}, La/b/k/h$i;->y(Landroid/widget/TextView;I)V

    :cond_3e
    if-eq v4, v14, :cond_3f

    iget-object v1, v0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-static {v1, v4}, La/b/k/h$i;->z(Landroid/widget/TextView;I)V

    :cond_3f
    return-void
.end method

.method public f(Landroid/content/Context;I)V
    .locals 3

    sget-object v0, La/b/j;->TextAppearance:[I

    .line 1
    new-instance v1, La/b/p/x0;

    invoke-virtual {p1, p2, v0}, Landroid/content/Context;->obtainStyledAttributes(I[I)Landroid/content/res/TypedArray;

    move-result-object p2

    invoke-direct {v1, p1, p2}, La/b/p/x0;-><init>(Landroid/content/Context;Landroid/content/res/TypedArray;)V

    .line 2
    sget p2, La/b/j;->TextAppearance_textAllCaps:I

    invoke-virtual {v1, p2}, La/b/p/x0;->m(I)Z

    move-result p2

    const/4 v0, 0x0

    if-eqz p2, :cond_0

    sget p2, La/b/j;->TextAppearance_textAllCaps:I

    invoke-virtual {v1, p2, v0}, La/b/p/x0;->a(IZ)Z

    move-result p2

    .line 3
    iget-object v2, p0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {v2, p2}, Landroid/widget/TextView;->setAllCaps(Z)V

    .line 4
    :cond_0
    sget p2, La/b/j;->TextAppearance_android_textSize:I

    invoke-virtual {v1, p2}, La/b/p/x0;->m(I)Z

    move-result p2

    if-eqz p2, :cond_1

    sget p2, La/b/j;->TextAppearance_android_textSize:I

    const/4 v2, -0x1

    invoke-virtual {v1, p2, v2}, La/b/p/x0;->d(II)I

    move-result p2

    if-nez p2, :cond_1

    iget-object p2, p0, La/b/p/y;->a:Landroid/widget/TextView;

    const/4 v2, 0x0

    invoke-virtual {p2, v0, v2}, Landroid/widget/TextView;->setTextSize(IF)V

    :cond_1
    invoke-virtual {p0, p1, v1}, La/b/p/y;->l(Landroid/content/Context;La/b/p/x0;)V

    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 p2, 0x1a

    if-lt p1, p2, :cond_2

    sget p1, La/b/j;->TextAppearance_fontVariationSettings:I

    invoke-virtual {v1, p1}, La/b/p/x0;->m(I)Z

    move-result p1

    if-eqz p1, :cond_2

    sget p1, La/b/j;->TextAppearance_fontVariationSettings:I

    invoke-virtual {v1, p1}, La/b/p/x0;->k(I)Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_2

    iget-object p2, p0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-virtual {p2, p1}, Landroid/widget/TextView;->setFontVariationSettings(Ljava/lang/String;)Z

    .line 5
    :cond_2
    iget-object p1, v1, La/b/p/x0;->b:Landroid/content/res/TypedArray;

    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    .line 6
    iget-object p1, p0, La/b/p/y;->l:Landroid/graphics/Typeface;

    if-eqz p1, :cond_3

    iget-object p2, p0, La/b/p/y;->a:Landroid/widget/TextView;

    iget v0, p0, La/b/p/y;->j:I

    invoke-virtual {p2, p1, v0}, Landroid/widget/TextView;->setTypeface(Landroid/graphics/Typeface;I)V

    :cond_3
    return-void
.end method

.method public g(IIII)V
    .locals 2

    iget-object v0, p0, La/b/p/y;->i:La/b/p/a0;

    .line 1
    invoke-virtual {v0}, La/b/p/a0;->i()Z

    move-result v1

    if-eqz v1, :cond_0

    iget-object v1, v0, La/b/p/a0;->j:Landroid/content/Context;

    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v1

    invoke-virtual {v1}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v1

    int-to-float p1, p1

    invoke-static {p4, p1, v1}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    move-result p1

    int-to-float p2, p2

    invoke-static {p4, p2, v1}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    move-result p2

    int-to-float p3, p3

    invoke-static {p4, p3, v1}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    move-result p3

    invoke-virtual {v0, p1, p2, p3}, La/b/p/a0;->j(FFF)V

    invoke-virtual {v0}, La/b/p/a0;->g()Z

    move-result p1

    if-eqz p1, :cond_0

    invoke-virtual {v0}, La/b/p/a0;->a()V

    :cond_0
    return-void
.end method

.method public h([II)V
    .locals 6

    iget-object v0, p0, La/b/p/y;->i:La/b/p/a0;

    .line 1
    invoke-virtual {v0}, La/b/p/a0;->i()Z

    move-result v1

    if-eqz v1, :cond_4

    array-length v1, p1

    const/4 v2, 0x0

    if-lez v1, :cond_3

    new-array v3, v1, [I

    if-nez p2, :cond_0

    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object v3

    goto :goto_1

    :cond_0
    iget-object v4, v0, La/b/p/a0;->j:Landroid/content/Context;

    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v4

    invoke-virtual {v4}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v4

    :goto_0
    if-ge v2, v1, :cond_1

    aget v5, p1, v2

    int-to-float v5, v5

    invoke-static {p2, v5, v4}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    move-result v5

    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    move-result v5

    aput v5, v3, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    :goto_1
    invoke-virtual {v0, v3}, La/b/p/a0;->b([I)[I

    move-result-object p2

    iput-object p2, v0, La/b/p/a0;->f:[I

    invoke-virtual {v0}, La/b/p/a0;->h()Z

    move-result p2

    if-eqz p2, :cond_2

    goto :goto_2

    :cond_2
    new-instance p2, Ljava/lang/IllegalArgumentException;

    const-string v0, "None of the preset sizes is valid: "

    invoke-static {v0}, Lb/a/a/a/a;->b(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-static {p1}, Ljava/util/Arrays;->toString([I)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_3
    iput-boolean v2, v0, La/b/p/a0;->g:Z

    :goto_2
    invoke-virtual {v0}, La/b/p/a0;->g()Z

    move-result p1

    if-eqz p1, :cond_4

    invoke-virtual {v0}, La/b/p/a0;->a()V

    :cond_4
    return-void
.end method

.method public i(I)V
    .locals 4

    iget-object v0, p0, La/b/p/y;->i:La/b/p/a0;

    .line 1
    invoke-virtual {v0}, La/b/p/a0;->i()Z

    move-result v1

    if-eqz v1, :cond_2

    if-eqz p1, :cond_1

    const/4 v1, 0x1

    if-ne p1, v1, :cond_0

    iget-object p1, v0, La/b/p/a0;->j:Landroid/content/Context;

    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p1

    invoke-virtual {p1}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object p1

    const/high16 v1, 0x41400000    # 12.0f

    const/4 v2, 0x2

    invoke-static {v2, v1, p1}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    move-result v1

    const/high16 v3, 0x42e00000    # 112.0f

    invoke-static {v2, v3, p1}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    move-result p1

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-virtual {v0, v1, p1, v2}, La/b/p/a0;->j(FFF)V

    invoke-virtual {v0}, La/b/p/a0;->g()Z

    move-result p1

    if-eqz p1, :cond_2

    invoke-virtual {v0}, La/b/p/a0;->a()V

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Unknown auto-size text type: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    const/4 p1, 0x0

    .line 2
    iput p1, v0, La/b/p/a0;->a:I

    const/high16 v1, -0x40800000    # -1.0f

    iput v1, v0, La/b/p/a0;->d:F

    iput v1, v0, La/b/p/a0;->e:F

    iput v1, v0, La/b/p/a0;->c:F

    new-array v1, p1, [I

    iput-object v1, v0, La/b/p/a0;->f:[I

    iput-boolean p1, v0, La/b/p/a0;->b:Z

    :cond_2
    :goto_0
    return-void
.end method

.method public j(Landroid/content/res/ColorStateList;)V
    .locals 1

    iget-object v0, p0, La/b/p/y;->h:La/b/p/v0;

    if-nez v0, :cond_0

    new-instance v0, La/b/p/v0;

    invoke-direct {v0}, La/b/p/v0;-><init>()V

    iput-object v0, p0, La/b/p/y;->h:La/b/p/v0;

    :cond_0
    iget-object v0, p0, La/b/p/y;->h:La/b/p/v0;

    iput-object p1, v0, La/b/p/v0;->a:Landroid/content/res/ColorStateList;

    if-eqz p1, :cond_1

    const/4 p1, 0x1

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    :goto_0
    iput-boolean p1, v0, La/b/p/v0;->d:Z

    .line 1
    iget-object p1, p0, La/b/p/y;->h:La/b/p/v0;

    iput-object p1, p0, La/b/p/y;->b:La/b/p/v0;

    iput-object p1, p0, La/b/p/y;->c:La/b/p/v0;

    iput-object p1, p0, La/b/p/y;->d:La/b/p/v0;

    iput-object p1, p0, La/b/p/y;->e:La/b/p/v0;

    iput-object p1, p0, La/b/p/y;->f:La/b/p/v0;

    iput-object p1, p0, La/b/p/y;->g:La/b/p/v0;

    return-void
.end method

.method public k(Landroid/graphics/PorterDuff$Mode;)V
    .locals 1

    iget-object v0, p0, La/b/p/y;->h:La/b/p/v0;

    if-nez v0, :cond_0

    new-instance v0, La/b/p/v0;

    invoke-direct {v0}, La/b/p/v0;-><init>()V

    iput-object v0, p0, La/b/p/y;->h:La/b/p/v0;

    :cond_0
    iget-object v0, p0, La/b/p/y;->h:La/b/p/v0;

    iput-object p1, v0, La/b/p/v0;->b:Landroid/graphics/PorterDuff$Mode;

    if-eqz p1, :cond_1

    const/4 p1, 0x1

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    :goto_0
    iput-boolean p1, v0, La/b/p/v0;->c:Z

    .line 1
    iget-object p1, p0, La/b/p/y;->h:La/b/p/v0;

    iput-object p1, p0, La/b/p/y;->b:La/b/p/v0;

    iput-object p1, p0, La/b/p/y;->c:La/b/p/v0;

    iput-object p1, p0, La/b/p/y;->d:La/b/p/v0;

    iput-object p1, p0, La/b/p/y;->e:La/b/p/v0;

    iput-object p1, p0, La/b/p/y;->f:La/b/p/v0;

    iput-object p1, p0, La/b/p/y;->g:La/b/p/v0;

    return-void
.end method

.method public final l(Landroid/content/Context;La/b/p/x0;)V
    .locals 9

    sget v0, La/b/j;->TextAppearance_android_textStyle:I

    iget v1, p0, La/b/p/y;->j:I

    invoke-virtual {p2, v0, v1}, La/b/p/x0;->h(II)I

    move-result v0

    iput v0, p0, La/b/p/y;->j:I

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1c

    const/4 v2, 0x2

    const/4 v3, -0x1

    const/4 v4, 0x0

    if-lt v0, v1, :cond_0

    sget v0, La/b/j;->TextAppearance_android_textFontWeight:I

    invoke-virtual {p2, v0, v3}, La/b/p/x0;->h(II)I

    move-result v0

    iput v0, p0, La/b/p/y;->k:I

    if-eq v0, v3, :cond_0

    iget v0, p0, La/b/p/y;->j:I

    and-int/2addr v0, v2

    or-int/2addr v0, v4

    iput v0, p0, La/b/p/y;->j:I

    :cond_0
    sget v0, La/b/j;->TextAppearance_android_fontFamily:I

    invoke-virtual {p2, v0}, La/b/p/x0;->m(I)Z

    move-result v0

    const/4 v5, 0x1

    if-nez v0, :cond_6

    sget v0, La/b/j;->TextAppearance_fontFamily:I

    invoke-virtual {p2, v0}, La/b/p/x0;->m(I)Z

    move-result v0

    if-eqz v0, :cond_1

    goto :goto_2

    :cond_1
    sget p1, La/b/j;->TextAppearance_android_typeface:I

    invoke-virtual {p2, p1}, La/b/p/x0;->m(I)Z

    move-result p1

    if-eqz p1, :cond_5

    iput-boolean v4, p0, La/b/p/y;->m:Z

    sget p1, La/b/j;->TextAppearance_android_typeface:I

    invoke-virtual {p2, p1, v5}, La/b/p/x0;->h(II)I

    move-result p1

    if-eq p1, v5, :cond_4

    if-eq p1, v2, :cond_3

    const/4 p2, 0x3

    if-eq p1, p2, :cond_2

    goto :goto_1

    :cond_2
    sget-object p1, Landroid/graphics/Typeface;->MONOSPACE:Landroid/graphics/Typeface;

    goto :goto_0

    :cond_3
    sget-object p1, Landroid/graphics/Typeface;->SERIF:Landroid/graphics/Typeface;

    goto :goto_0

    :cond_4
    sget-object p1, Landroid/graphics/Typeface;->SANS_SERIF:Landroid/graphics/Typeface;

    :goto_0
    iput-object p1, p0, La/b/p/y;->l:Landroid/graphics/Typeface;

    :cond_5
    :goto_1
    return-void

    :cond_6
    :goto_2
    const/4 v0, 0x0

    iput-object v0, p0, La/b/p/y;->l:Landroid/graphics/Typeface;

    sget v0, La/b/j;->TextAppearance_fontFamily:I

    invoke-virtual {p2, v0}, La/b/p/x0;->m(I)Z

    move-result v0

    if-eqz v0, :cond_7

    sget v0, La/b/j;->TextAppearance_fontFamily:I

    goto :goto_3

    :cond_7
    sget v0, La/b/j;->TextAppearance_android_fontFamily:I

    :goto_3
    iget v6, p0, La/b/p/y;->k:I

    iget v7, p0, La/b/p/y;->j:I

    invoke-virtual {p1}, Landroid/content/Context;->isRestricted()Z

    move-result p1

    if-nez p1, :cond_c

    new-instance p1, Ljava/lang/ref/WeakReference;

    iget-object v8, p0, La/b/p/y;->a:Landroid/widget/TextView;

    invoke-direct {p1, v8}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    new-instance v8, La/b/p/y$a;

    invoke-direct {v8, p0, v6, v7, p1}, La/b/p/y$a;-><init>(La/b/p/y;IILjava/lang/ref/WeakReference;)V

    :try_start_0
    iget p1, p0, La/b/p/y;->j:I

    invoke-virtual {p2, v0, p1, v8}, La/b/p/x0;->g(IILa/f/d/b/e;)Landroid/graphics/Typeface;

    move-result-object p1

    if-eqz p1, :cond_a

    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v6, v1, :cond_9

    iget v6, p0, La/b/p/y;->k:I

    if-eq v6, v3, :cond_9

    invoke-static {p1, v4}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    move-result-object p1

    iget v6, p0, La/b/p/y;->k:I

    iget v7, p0, La/b/p/y;->j:I

    and-int/2addr v7, v2

    if-eqz v7, :cond_8

    move v7, v5

    goto :goto_4

    :cond_8
    move v7, v4

    :goto_4
    invoke-static {p1, v6, v7}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;IZ)Landroid/graphics/Typeface;

    move-result-object p1

    :cond_9
    iput-object p1, p0, La/b/p/y;->l:Landroid/graphics/Typeface;

    :cond_a
    iget-object p1, p0, La/b/p/y;->l:Landroid/graphics/Typeface;

    if-nez p1, :cond_b

    move p1, v5

    goto :goto_5

    :cond_b
    move p1, v4

    :goto_5
    iput-boolean p1, p0, La/b/p/y;->m:Z
    :try_end_0
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    :cond_c
    iget-object p1, p0, La/b/p/y;->l:Landroid/graphics/Typeface;

    if-nez p1, :cond_f

    invoke-virtual {p2, v0}, La/b/p/x0;->k(I)Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_f

    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt p2, v1, :cond_e

    iget p2, p0, La/b/p/y;->k:I

    if-eq p2, v3, :cond_e

    invoke-static {p1, v4}, Landroid/graphics/Typeface;->create(Ljava/lang/String;I)Landroid/graphics/Typeface;

    move-result-object p1

    iget p2, p0, La/b/p/y;->k:I

    iget v0, p0, La/b/p/y;->j:I

    and-int/2addr v0, v2

    if-eqz v0, :cond_d

    move v4, v5

    :cond_d
    invoke-static {p1, p2, v4}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;IZ)Landroid/graphics/Typeface;

    move-result-object p1

    goto :goto_6

    :cond_e
    iget p2, p0, La/b/p/y;->j:I

    invoke-static {p1, p2}, Landroid/graphics/Typeface;->create(Ljava/lang/String;I)Landroid/graphics/Typeface;

    move-result-object p1

    :goto_6
    iput-object p1, p0, La/b/p/y;->l:Landroid/graphics/Typeface;

    :cond_f
    return-void
.end method
