.class public La/b/k/d;
.super La/b/k/n;
.source ""

# interfaces
.implements Landroid/content/DialogInterface;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/b/k/d$a;
    }
.end annotation


# instance fields
.field public final d:Landroidx/appcompat/app/AlertController;


# direct methods
.method public constructor <init>(Landroid/content/Context;I)V
    .locals 1

    invoke-static {p1, p2}, La/b/k/d;->d(Landroid/content/Context;I)I

    move-result p2

    invoke-direct {p0, p1, p2}, La/b/k/n;-><init>(Landroid/content/Context;I)V

    new-instance p1, Landroidx/appcompat/app/AlertController;

    invoke-virtual {p0}, Landroid/app/Dialog;->getContext()Landroid/content/Context;

    move-result-object p2

    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    move-result-object v0

    invoke-direct {p1, p2, p0, v0}, Landroidx/appcompat/app/AlertController;-><init>(Landroid/content/Context;La/b/k/n;Landroid/view/Window;)V

    iput-object p1, p0, La/b/k/d;->d:Landroidx/appcompat/app/AlertController;

    return-void
.end method

.method public static d(Landroid/content/Context;I)I
    .locals 2

    ushr-int/lit8 v0, p1, 0x18

    and-int/lit16 v0, v0, 0xff

    const/4 v1, 0x1

    if-lt v0, v1, :cond_0

    return p1

    :cond_0
    new-instance p1, Landroid/util/TypedValue;

    invoke-direct {p1}, Landroid/util/TypedValue;-><init>()V

    invoke-virtual {p0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object p0

    sget v0, La/b/a;->alertDialogTheme:I

    invoke-virtual {p0, v0, p1, v1}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    iget p0, p1, Landroid/util/TypedValue;->resourceId:I

    return p0
.end method


# virtual methods
.method public onCreate(Landroid/os/Bundle;)V
    .locals 16

    invoke-super/range {p0 .. p1}, La/b/k/n;->onCreate(Landroid/os/Bundle;)V

    move-object/from16 v0, p0

    iget-object v1, v0, La/b/k/d;->d:Landroidx/appcompat/app/AlertController;

    .line 1
    iget v2, v1, Landroidx/appcompat/app/AlertController;->K:I

    const/4 v3, 0x1

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    iget v4, v1, Landroidx/appcompat/app/AlertController;->Q:I

    if-ne v4, v3, :cond_1

    goto :goto_1

    :cond_1
    :goto_0
    iget v2, v1, Landroidx/appcompat/app/AlertController;->J:I

    .line 2
    :goto_1
    iget-object v4, v1, Landroidx/appcompat/app/AlertController;->b:La/b/k/n;

    invoke-virtual {v4, v2}, La/b/k/n;->setContentView(I)V

    .line 3
    iget-object v2, v1, Landroidx/appcompat/app/AlertController;->c:Landroid/view/Window;

    sget v4, La/b/f;->parentPanel:I

    invoke-virtual {v2, v4}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    move-result-object v2

    sget v4, La/b/f;->topPanel:I

    invoke-virtual {v2, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v4

    sget v5, La/b/f;->contentPanel:I

    invoke-virtual {v2, v5}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v5

    sget v6, La/b/f;->buttonPanel:I

    invoke-virtual {v2, v6}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v6

    sget v7, La/b/f;->customPanel:I

    invoke-virtual {v2, v7}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v2

    check-cast v2, Landroid/view/ViewGroup;

    .line 4
    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->h:Landroid/view/View;

    const/4 v8, 0x0

    const/4 v9, 0x0

    if-eqz v7, :cond_2

    goto :goto_2

    :cond_2
    iget v7, v1, Landroidx/appcompat/app/AlertController;->i:I

    if-eqz v7, :cond_3

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->a:Landroid/content/Context;

    invoke-static {v7}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v7

    iget v10, v1, Landroidx/appcompat/app/AlertController;->i:I

    invoke-virtual {v7, v10, v2, v9}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    move-result-object v7

    goto :goto_2

    :cond_3
    move-object v7, v8

    :goto_2
    if-eqz v7, :cond_4

    move v10, v3

    goto :goto_3

    :cond_4
    move v10, v9

    :goto_3
    if-eqz v10, :cond_5

    invoke-static {v7}, Landroidx/appcompat/app/AlertController;->a(Landroid/view/View;)Z

    move-result v11

    if-nez v11, :cond_6

    :cond_5
    iget-object v11, v1, Landroidx/appcompat/app/AlertController;->c:Landroid/view/Window;

    const/high16 v12, 0x20000

    invoke-virtual {v11, v12, v12}, Landroid/view/Window;->setFlags(II)V

    :cond_6
    const/4 v11, -0x1

    const/16 v12, 0x8

    if-eqz v10, :cond_8

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->c:Landroid/view/Window;

    sget v13, La/b/f;->custom:I

    invoke-virtual {v10, v13}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    move-result-object v10

    check-cast v10, Landroid/widget/FrameLayout;

    new-instance v13, Landroid/view/ViewGroup$LayoutParams;

    invoke-direct {v13, v11, v11}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    invoke-virtual {v10, v7, v13}, Landroid/widget/FrameLayout;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    iget-boolean v7, v1, Landroidx/appcompat/app/AlertController;->n:Z

    if-eqz v7, :cond_7

    iget v7, v1, Landroidx/appcompat/app/AlertController;->j:I

    iget v13, v1, Landroidx/appcompat/app/AlertController;->k:I

    iget v14, v1, Landroidx/appcompat/app/AlertController;->l:I

    iget v15, v1, Landroidx/appcompat/app/AlertController;->m:I

    invoke-virtual {v10, v7, v13, v14, v15}, Landroid/widget/FrameLayout;->setPadding(IIII)V

    :cond_7
    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->g:Landroid/widget/ListView;

    if-eqz v7, :cond_9

    invoke-virtual {v2}, Landroid/view/ViewGroup;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v7

    check-cast v7, La/b/p/i0$a;

    const/4 v10, 0x0

    iput v10, v7, La/b/p/i0$a;->a:F

    goto :goto_4

    :cond_8
    invoke-virtual {v2, v12}, Landroid/view/ViewGroup;->setVisibility(I)V

    .line 5
    :cond_9
    :goto_4
    sget v7, La/b/f;->topPanel:I

    invoke-virtual {v2, v7}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v7

    sget v10, La/b/f;->contentPanel:I

    invoke-virtual {v2, v10}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v10

    sget v13, La/b/f;->buttonPanel:I

    invoke-virtual {v2, v13}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v13

    invoke-virtual {v1, v7, v4}, Landroidx/appcompat/app/AlertController;->d(Landroid/view/View;Landroid/view/View;)Landroid/view/ViewGroup;

    move-result-object v4

    invoke-virtual {v1, v10, v5}, Landroidx/appcompat/app/AlertController;->d(Landroid/view/View;Landroid/view/View;)Landroid/view/ViewGroup;

    move-result-object v5

    invoke-virtual {v1, v13, v6}, Landroidx/appcompat/app/AlertController;->d(Landroid/view/View;Landroid/view/View;)Landroid/view/ViewGroup;

    move-result-object v6

    .line 6
    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->c:Landroid/view/Window;

    sget v10, La/b/f;->scrollView:I

    invoke-virtual {v7, v10}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    move-result-object v7

    check-cast v7, Landroidx/core/widget/NestedScrollView;

    iput-object v7, v1, Landroidx/appcompat/app/AlertController;->A:Landroidx/core/widget/NestedScrollView;

    invoke-virtual {v7, v9}, Landroid/widget/FrameLayout;->setFocusable(Z)V

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->A:Landroidx/core/widget/NestedScrollView;

    invoke-virtual {v7, v9}, Landroidx/core/widget/NestedScrollView;->setNestedScrollingEnabled(Z)V

    const v7, 0x102000b

    invoke-virtual {v5, v7}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v7

    check-cast v7, Landroid/widget/TextView;

    iput-object v7, v1, Landroidx/appcompat/app/AlertController;->F:Landroid/widget/TextView;

    if-nez v7, :cond_a

    goto :goto_5

    :cond_a
    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->f:Ljava/lang/CharSequence;

    if-eqz v10, :cond_b

    invoke-virtual {v7, v10}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    goto :goto_5

    :cond_b
    invoke-virtual {v7, v12}, Landroid/widget/TextView;->setVisibility(I)V

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->A:Landroidx/core/widget/NestedScrollView;

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->F:Landroid/widget/TextView;

    invoke-virtual {v7, v10}, Landroid/widget/FrameLayout;->removeView(Landroid/view/View;)V

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->g:Landroid/widget/ListView;

    if-eqz v7, :cond_c

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->A:Landroidx/core/widget/NestedScrollView;

    invoke-virtual {v7}, Landroid/widget/FrameLayout;->getParent()Landroid/view/ViewParent;

    move-result-object v7

    check-cast v7, Landroid/view/ViewGroup;

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->A:Landroidx/core/widget/NestedScrollView;

    invoke-virtual {v7, v10}, Landroid/view/ViewGroup;->indexOfChild(Landroid/view/View;)I

    move-result v10

    invoke-virtual {v7, v10}, Landroid/view/ViewGroup;->removeViewAt(I)V

    iget-object v13, v1, Landroidx/appcompat/app/AlertController;->g:Landroid/widget/ListView;

    new-instance v14, Landroid/view/ViewGroup$LayoutParams;

    invoke-direct {v14, v11, v11}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    invoke-virtual {v7, v13, v10, v14}, Landroid/view/ViewGroup;->addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V

    goto :goto_5

    :cond_c
    invoke-virtual {v5, v12}, Landroid/view/ViewGroup;->setVisibility(I)V

    :goto_5
    const v7, 0x1020019

    .line 7
    invoke-virtual {v6, v7}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v7

    check-cast v7, Landroid/widget/Button;

    iput-object v7, v1, Landroidx/appcompat/app/AlertController;->o:Landroid/widget/Button;

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->S:Landroid/view/View$OnClickListener;

    invoke-virtual {v7, v10}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->p:Ljava/lang/CharSequence;

    invoke-static {v7}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v7

    if-eqz v7, :cond_d

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->r:Landroid/graphics/drawable/Drawable;

    if-nez v7, :cond_d

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->o:Landroid/widget/Button;

    invoke-virtual {v7, v12}, Landroid/widget/Button;->setVisibility(I)V

    move v7, v9

    goto :goto_6

    :cond_d
    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->o:Landroid/widget/Button;

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->p:Ljava/lang/CharSequence;

    invoke-virtual {v7, v10}, Landroid/widget/Button;->setText(Ljava/lang/CharSequence;)V

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->r:Landroid/graphics/drawable/Drawable;

    if-eqz v7, :cond_e

    iget v10, v1, Landroidx/appcompat/app/AlertController;->d:I

    invoke-virtual {v7, v9, v9, v10, v10}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->o:Landroid/widget/Button;

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->r:Landroid/graphics/drawable/Drawable;

    invoke-virtual {v7, v10, v8, v8, v8}, Landroid/widget/Button;->setCompoundDrawables(Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;)V

    :cond_e
    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->o:Landroid/widget/Button;

    invoke-virtual {v7, v9}, Landroid/widget/Button;->setVisibility(I)V

    move v7, v3

    :goto_6
    const v10, 0x102001a

    invoke-virtual {v6, v10}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v10

    check-cast v10, Landroid/widget/Button;

    iput-object v10, v1, Landroidx/appcompat/app/AlertController;->s:Landroid/widget/Button;

    iget-object v13, v1, Landroidx/appcompat/app/AlertController;->S:Landroid/view/View$OnClickListener;

    invoke-virtual {v10, v13}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->t:Ljava/lang/CharSequence;

    invoke-static {v10}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v10

    if-eqz v10, :cond_f

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->v:Landroid/graphics/drawable/Drawable;

    if-nez v10, :cond_f

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->s:Landroid/widget/Button;

    invoke-virtual {v10, v12}, Landroid/widget/Button;->setVisibility(I)V

    goto :goto_7

    :cond_f
    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->s:Landroid/widget/Button;

    iget-object v13, v1, Landroidx/appcompat/app/AlertController;->t:Ljava/lang/CharSequence;

    invoke-virtual {v10, v13}, Landroid/widget/Button;->setText(Ljava/lang/CharSequence;)V

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->v:Landroid/graphics/drawable/Drawable;

    if-eqz v10, :cond_10

    iget v13, v1, Landroidx/appcompat/app/AlertController;->d:I

    invoke-virtual {v10, v9, v9, v13, v13}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->s:Landroid/widget/Button;

    iget-object v13, v1, Landroidx/appcompat/app/AlertController;->v:Landroid/graphics/drawable/Drawable;

    invoke-virtual {v10, v13, v8, v8, v8}, Landroid/widget/Button;->setCompoundDrawables(Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;)V

    :cond_10
    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->s:Landroid/widget/Button;

    invoke-virtual {v10, v9}, Landroid/widget/Button;->setVisibility(I)V

    or-int/lit8 v7, v7, 0x2

    :goto_7
    const v10, 0x102001b

    invoke-virtual {v6, v10}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v10

    check-cast v10, Landroid/widget/Button;

    iput-object v10, v1, Landroidx/appcompat/app/AlertController;->w:Landroid/widget/Button;

    iget-object v13, v1, Landroidx/appcompat/app/AlertController;->S:Landroid/view/View$OnClickListener;

    invoke-virtual {v10, v13}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->x:Ljava/lang/CharSequence;

    invoke-static {v10}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v10

    if-eqz v10, :cond_11

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->z:Landroid/graphics/drawable/Drawable;

    if-nez v10, :cond_11

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->w:Landroid/widget/Button;

    invoke-virtual {v10, v12}, Landroid/widget/Button;->setVisibility(I)V

    goto :goto_8

    :cond_11
    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->w:Landroid/widget/Button;

    iget-object v13, v1, Landroidx/appcompat/app/AlertController;->x:Ljava/lang/CharSequence;

    invoke-virtual {v10, v13}, Landroid/widget/Button;->setText(Ljava/lang/CharSequence;)V

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->z:Landroid/graphics/drawable/Drawable;

    if-eqz v10, :cond_12

    iget v13, v1, Landroidx/appcompat/app/AlertController;->d:I

    invoke-virtual {v10, v9, v9, v13, v13}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->w:Landroid/widget/Button;

    iget-object v13, v1, Landroidx/appcompat/app/AlertController;->z:Landroid/graphics/drawable/Drawable;

    invoke-virtual {v10, v13, v8, v8, v8}, Landroid/widget/Button;->setCompoundDrawables(Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;)V

    :cond_12
    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->w:Landroid/widget/Button;

    invoke-virtual {v10, v9}, Landroid/widget/Button;->setVisibility(I)V

    or-int/lit8 v7, v7, 0x4

    :goto_8
    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->a:Landroid/content/Context;

    .line 8
    new-instance v13, Landroid/util/TypedValue;

    invoke-direct {v13}, Landroid/util/TypedValue;-><init>()V

    invoke-virtual {v10}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v10

    sget v14, La/b/a;->alertDialogCenterButtons:I

    invoke-virtual {v10, v14, v13, v3}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    iget v10, v13, Landroid/util/TypedValue;->data:I

    if-eqz v10, :cond_13

    move v10, v3

    goto :goto_9

    :cond_13
    move v10, v9

    :goto_9
    const/4 v13, 0x2

    if-eqz v10, :cond_16

    if-ne v7, v3, :cond_14

    .line 9
    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->o:Landroid/widget/Button;

    goto :goto_a

    :cond_14
    if-ne v7, v13, :cond_15

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->s:Landroid/widget/Button;

    goto :goto_a

    :cond_15
    const/4 v10, 0x4

    if-ne v7, v10, :cond_16

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->w:Landroid/widget/Button;

    :goto_a
    invoke-virtual {v1, v10}, Landroidx/appcompat/app/AlertController;->b(Landroid/widget/Button;)V

    :cond_16
    if-eqz v7, :cond_17

    move v7, v3

    goto :goto_b

    :cond_17
    move v7, v9

    :goto_b
    if-nez v7, :cond_18

    invoke-virtual {v6, v12}, Landroid/view/ViewGroup;->setVisibility(I)V

    .line 10
    :cond_18
    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->G:Landroid/view/View;

    if-eqz v7, :cond_19

    new-instance v7, Landroid/view/ViewGroup$LayoutParams;

    const/4 v10, -0x2

    invoke-direct {v7, v11, v10}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->G:Landroid/view/View;

    invoke-virtual {v4, v10, v9, v7}, Landroid/view/ViewGroup;->addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->c:Landroid/view/Window;

    sget v10, La/b/f;->title_template:I

    invoke-virtual {v7, v10}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    move-result-object v7

    invoke-virtual {v7, v12}, Landroid/view/View;->setVisibility(I)V

    goto/16 :goto_c

    :cond_19
    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->c:Landroid/view/Window;

    const v10, 0x1020006

    invoke-virtual {v7, v10}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    move-result-object v7

    check-cast v7, Landroid/widget/ImageView;

    iput-object v7, v1, Landroidx/appcompat/app/AlertController;->D:Landroid/widget/ImageView;

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->e:Ljava/lang/CharSequence;

    invoke-static {v7}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v7

    xor-int/2addr v7, v3

    if-eqz v7, :cond_1c

    iget-boolean v7, v1, Landroidx/appcompat/app/AlertController;->P:Z

    if-eqz v7, :cond_1c

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->c:Landroid/view/Window;

    sget v10, La/b/f;->alertTitle:I

    invoke-virtual {v7, v10}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    move-result-object v7

    check-cast v7, Landroid/widget/TextView;

    iput-object v7, v1, Landroidx/appcompat/app/AlertController;->E:Landroid/widget/TextView;

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->e:Ljava/lang/CharSequence;

    invoke-virtual {v7, v10}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    iget v7, v1, Landroidx/appcompat/app/AlertController;->B:I

    if-eqz v7, :cond_1a

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->D:Landroid/widget/ImageView;

    invoke-virtual {v10, v7}, Landroid/widget/ImageView;->setImageResource(I)V

    goto :goto_c

    :cond_1a
    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->C:Landroid/graphics/drawable/Drawable;

    if-eqz v7, :cond_1b

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->D:Landroid/widget/ImageView;

    invoke-virtual {v10, v7}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    goto :goto_c

    :cond_1b
    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->E:Landroid/widget/TextView;

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->D:Landroid/widget/ImageView;

    invoke-virtual {v10}, Landroid/widget/ImageView;->getPaddingLeft()I

    move-result v10

    iget-object v14, v1, Landroidx/appcompat/app/AlertController;->D:Landroid/widget/ImageView;

    invoke-virtual {v14}, Landroid/widget/ImageView;->getPaddingTop()I

    move-result v14

    iget-object v15, v1, Landroidx/appcompat/app/AlertController;->D:Landroid/widget/ImageView;

    invoke-virtual {v15}, Landroid/widget/ImageView;->getPaddingRight()I

    move-result v15

    iget-object v13, v1, Landroidx/appcompat/app/AlertController;->D:Landroid/widget/ImageView;

    invoke-virtual {v13}, Landroid/widget/ImageView;->getPaddingBottom()I

    move-result v13

    invoke-virtual {v7, v10, v14, v15, v13}, Landroid/widget/TextView;->setPadding(IIII)V

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->D:Landroid/widget/ImageView;

    invoke-virtual {v7, v12}, Landroid/widget/ImageView;->setVisibility(I)V

    goto :goto_c

    :cond_1c
    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->c:Landroid/view/Window;

    sget v10, La/b/f;->title_template:I

    invoke-virtual {v7, v10}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    move-result-object v7

    invoke-virtual {v7, v12}, Landroid/view/View;->setVisibility(I)V

    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->D:Landroid/widget/ImageView;

    invoke-virtual {v7, v12}, Landroid/widget/ImageView;->setVisibility(I)V

    invoke-virtual {v4, v12}, Landroid/view/ViewGroup;->setVisibility(I)V

    .line 11
    :goto_c
    invoke-virtual {v2}, Landroid/view/ViewGroup;->getVisibility()I

    move-result v2

    if-eq v2, v12, :cond_1d

    move v2, v3

    goto :goto_d

    :cond_1d
    move v2, v9

    :goto_d
    if-eqz v4, :cond_1e

    invoke-virtual {v4}, Landroid/view/ViewGroup;->getVisibility()I

    move-result v7

    if-eq v7, v12, :cond_1e

    move v7, v3

    goto :goto_e

    :cond_1e
    move v7, v9

    :goto_e
    invoke-virtual {v6}, Landroid/view/ViewGroup;->getVisibility()I

    move-result v6

    if-eq v6, v12, :cond_1f

    move v6, v3

    goto :goto_f

    :cond_1f
    move v6, v9

    :goto_f
    if-nez v6, :cond_20

    sget v10, La/b/f;->textSpacerNoButtons:I

    invoke-virtual {v5, v10}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v10

    if-eqz v10, :cond_20

    invoke-virtual {v10, v9}, Landroid/view/View;->setVisibility(I)V

    :cond_20
    if-eqz v7, :cond_24

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->A:Landroidx/core/widget/NestedScrollView;

    if-eqz v10, :cond_21

    invoke-virtual {v10, v3}, Landroid/widget/FrameLayout;->setClipToPadding(Z)V

    :cond_21
    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->f:Ljava/lang/CharSequence;

    if-nez v10, :cond_23

    iget-object v10, v1, Landroidx/appcompat/app/AlertController;->g:Landroid/widget/ListView;

    if-eqz v10, :cond_22

    goto :goto_10

    :cond_22
    move-object v4, v8

    goto :goto_11

    :cond_23
    :goto_10
    sget v10, La/b/f;->titleDividerNoCustom:I

    invoke-virtual {v4, v10}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v4

    :goto_11
    if-eqz v4, :cond_25

    goto :goto_12

    :cond_24
    sget v4, La/b/f;->textSpacerNoTitle:I

    invoke-virtual {v5, v4}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v4

    if-eqz v4, :cond_25

    :goto_12
    invoke-virtual {v4, v9}, Landroid/view/View;->setVisibility(I)V

    :cond_25
    iget-object v4, v1, Landroidx/appcompat/app/AlertController;->g:Landroid/widget/ListView;

    instance-of v10, v4, Landroidx/appcompat/app/AlertController$RecycleListView;

    if-eqz v10, :cond_2a

    check-cast v4, Landroidx/appcompat/app/AlertController$RecycleListView;

    if-eqz v4, :cond_29

    if-eqz v6, :cond_26

    if-nez v7, :cond_2a

    .line 12
    :cond_26
    invoke-virtual {v4}, Landroid/widget/ListView;->getPaddingLeft()I

    move-result v8

    if-eqz v7, :cond_27

    invoke-virtual {v4}, Landroid/widget/ListView;->getPaddingTop()I

    move-result v10

    goto :goto_13

    :cond_27
    iget v10, v4, Landroidx/appcompat/app/AlertController$RecycleListView;->b:I

    :goto_13
    invoke-virtual {v4}, Landroid/widget/ListView;->getPaddingRight()I

    move-result v12

    if-eqz v6, :cond_28

    invoke-virtual {v4}, Landroid/widget/ListView;->getPaddingBottom()I

    move-result v13

    goto :goto_14

    :cond_28
    iget v13, v4, Landroidx/appcompat/app/AlertController$RecycleListView;->c:I

    :goto_14
    invoke-virtual {v4, v8, v10, v12, v13}, Landroid/widget/ListView;->setPadding(IIII)V

    goto :goto_15

    :cond_29
    throw v8

    :cond_2a
    :goto_15
    if-nez v2, :cond_2e

    .line 13
    iget-object v2, v1, Landroidx/appcompat/app/AlertController;->g:Landroid/widget/ListView;

    if-eqz v2, :cond_2b

    goto :goto_16

    :cond_2b
    iget-object v2, v1, Landroidx/appcompat/app/AlertController;->A:Landroidx/core/widget/NestedScrollView;

    :goto_16
    if-eqz v2, :cond_2e

    if-eqz v6, :cond_2c

    const/4 v9, 0x2

    :cond_2c
    or-int v4, v7, v9

    const/4 v6, 0x3

    .line 14
    iget-object v7, v1, Landroidx/appcompat/app/AlertController;->c:Landroid/view/Window;

    sget v8, La/b/f;->scrollIndicatorUp:I

    invoke-virtual {v7, v8}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    move-result-object v7

    iget-object v8, v1, Landroidx/appcompat/app/AlertController;->c:Landroid/view/Window;

    sget v9, La/b/f;->scrollIndicatorDown:I

    invoke-virtual {v8, v9}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    move-result-object v8

    invoke-static {v2, v4, v6}, La/f/j/k;->y(Landroid/view/View;II)V

    if-eqz v7, :cond_2d

    invoke-virtual {v5, v7}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    :cond_2d
    if-eqz v8, :cond_2e

    invoke-virtual {v5, v8}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 15
    :cond_2e
    iget-object v2, v1, Landroidx/appcompat/app/AlertController;->g:Landroid/widget/ListView;

    if-eqz v2, :cond_2f

    iget-object v4, v1, Landroidx/appcompat/app/AlertController;->H:Landroid/widget/ListAdapter;

    if-eqz v4, :cond_2f

    invoke-virtual {v2, v4}, Landroid/widget/ListView;->setAdapter(Landroid/widget/ListAdapter;)V

    iget v1, v1, Landroidx/appcompat/app/AlertController;->I:I

    if-le v1, v11, :cond_2f

    invoke-virtual {v2, v1, v3}, Landroid/widget/ListView;->setItemChecked(IZ)V

    invoke-virtual {v2, v1}, Landroid/widget/ListView;->setSelection(I)V

    :cond_2f
    return-void
.end method

.method public onKeyDown(ILandroid/view/KeyEvent;)Z
    .locals 2

    iget-object v0, p0, La/b/k/d;->d:Landroidx/appcompat/app/AlertController;

    .line 1
    iget-object v0, v0, Landroidx/appcompat/app/AlertController;->A:Landroidx/core/widget/NestedScrollView;

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    invoke-virtual {v0, p2}, Landroidx/core/widget/NestedScrollView;->h(Landroid/view/KeyEvent;)Z

    move-result v0

    if-eqz v0, :cond_0

    move v0, v1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    return v1

    .line 2
    :cond_1
    invoke-super {p0, p1, p2}, Landroid/app/Dialog;->onKeyDown(ILandroid/view/KeyEvent;)Z

    move-result p1

    return p1
.end method

.method public onKeyUp(ILandroid/view/KeyEvent;)Z
    .locals 2

    iget-object v0, p0, La/b/k/d;->d:Landroidx/appcompat/app/AlertController;

    .line 1
    iget-object v0, v0, Landroidx/appcompat/app/AlertController;->A:Landroidx/core/widget/NestedScrollView;

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    invoke-virtual {v0, p2}, Landroidx/core/widget/NestedScrollView;->h(Landroid/view/KeyEvent;)Z

    move-result v0

    if-eqz v0, :cond_0

    move v0, v1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    return v1

    .line 2
    :cond_1
    invoke-super {p0, p1, p2}, Landroid/app/Dialog;->onKeyUp(ILandroid/view/KeyEvent;)Z

    move-result p1

    return p1
.end method

.method public setTitle(Ljava/lang/CharSequence;)V
    .locals 1

    invoke-super {p0, p1}, La/b/k/n;->setTitle(Ljava/lang/CharSequence;)V

    iget-object v0, p0, La/b/k/d;->d:Landroidx/appcompat/app/AlertController;

    .line 1
    iput-object p1, v0, Landroidx/appcompat/app/AlertController;->e:Ljava/lang/CharSequence;

    iget-object v0, v0, Landroidx/appcompat/app/AlertController;->E:Landroid/widget/TextView;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    :cond_0
    return-void
.end method
