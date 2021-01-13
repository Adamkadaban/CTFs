.class public La/b/p/z0;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements La/b/p/d0;


# instance fields
.field public a:Landroidx/appcompat/widget/Toolbar;

.field public b:I

.field public c:Landroid/view/View;

.field public d:Landroid/view/View;

.field public e:Landroid/graphics/drawable/Drawable;

.field public f:Landroid/graphics/drawable/Drawable;

.field public g:Landroid/graphics/drawable/Drawable;

.field public h:Z

.field public i:Ljava/lang/CharSequence;

.field public j:Ljava/lang/CharSequence;

.field public k:Ljava/lang/CharSequence;

.field public l:Landroid/view/Window$Callback;

.field public m:Z

.field public n:La/b/p/c;

.field public o:I

.field public p:I

.field public q:Landroid/graphics/drawable/Drawable;


# direct methods
.method public constructor <init>(Landroidx/appcompat/widget/Toolbar;Z)V
    .locals 6

    sget v0, La/b/h;->abc_action_bar_up_description:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v1, 0x0

    iput v1, p0, La/b/p/z0;->o:I

    iput v1, p0, La/b/p/z0;->p:I

    iput-object p1, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {p1}, Landroidx/appcompat/widget/Toolbar;->getTitle()Ljava/lang/CharSequence;

    move-result-object v2

    iput-object v2, p0, La/b/p/z0;->i:Ljava/lang/CharSequence;

    invoke-virtual {p1}, Landroidx/appcompat/widget/Toolbar;->getSubtitle()Ljava/lang/CharSequence;

    move-result-object v2

    iput-object v2, p0, La/b/p/z0;->j:Ljava/lang/CharSequence;

    iget-object v2, p0, La/b/p/z0;->i:Ljava/lang/CharSequence;

    const/4 v3, 0x1

    if-eqz v2, :cond_0

    move v2, v3

    goto :goto_0

    :cond_0
    move v2, v1

    :goto_0
    iput-boolean v2, p0, La/b/p/z0;->h:Z

    invoke-virtual {p1}, Landroidx/appcompat/widget/Toolbar;->getNavigationIcon()Landroid/graphics/drawable/Drawable;

    move-result-object v2

    iput-object v2, p0, La/b/p/z0;->g:Landroid/graphics/drawable/Drawable;

    invoke-virtual {p1}, Landroid/view/ViewGroup;->getContext()Landroid/content/Context;

    move-result-object p1

    sget-object v2, La/b/j;->ActionBar:[I

    sget v4, La/b/a;->actionBarStyle:I

    const/4 v5, 0x0

    invoke-static {p1, v5, v2, v4, v1}, La/b/p/x0;->o(Landroid/content/Context;Landroid/util/AttributeSet;[III)La/b/p/x0;

    move-result-object p1

    sget v2, La/b/j;->ActionBar_homeAsUpIndicator:I

    invoke-virtual {p1, v2}, La/b/p/x0;->e(I)Landroid/graphics/drawable/Drawable;

    move-result-object v2

    iput-object v2, p0, La/b/p/z0;->q:Landroid/graphics/drawable/Drawable;

    if-eqz p2, :cond_e

    sget p2, La/b/j;->ActionBar_title:I

    invoke-virtual {p1, p2}, La/b/p/x0;->l(I)Ljava/lang/CharSequence;

    move-result-object p2

    invoke-static {p2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_1

    .line 2
    iput-boolean v3, p0, La/b/p/z0;->h:Z

    .line 3
    iput-object p2, p0, La/b/p/z0;->i:Ljava/lang/CharSequence;

    iget v2, p0, La/b/p/z0;->b:I

    and-int/lit8 v2, v2, 0x8

    if-eqz v2, :cond_1

    iget-object v2, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v2, p2}, Landroidx/appcompat/widget/Toolbar;->setTitle(Ljava/lang/CharSequence;)V

    .line 4
    :cond_1
    sget p2, La/b/j;->ActionBar_subtitle:I

    invoke-virtual {p1, p2}, La/b/p/x0;->l(I)Ljava/lang/CharSequence;

    move-result-object p2

    invoke-static {p2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_2

    .line 5
    iput-object p2, p0, La/b/p/z0;->j:Ljava/lang/CharSequence;

    iget v2, p0, La/b/p/z0;->b:I

    and-int/lit8 v2, v2, 0x8

    if-eqz v2, :cond_2

    iget-object v2, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v2, p2}, Landroidx/appcompat/widget/Toolbar;->setSubtitle(Ljava/lang/CharSequence;)V

    .line 6
    :cond_2
    sget p2, La/b/j;->ActionBar_logo:I

    invoke-virtual {p1, p2}, La/b/p/x0;->e(I)Landroid/graphics/drawable/Drawable;

    move-result-object p2

    if-eqz p2, :cond_3

    .line 7
    iput-object p2, p0, La/b/p/z0;->f:Landroid/graphics/drawable/Drawable;

    invoke-virtual {p0}, La/b/p/z0;->y()V

    .line 8
    :cond_3
    sget p2, La/b/j;->ActionBar_icon:I

    invoke-virtual {p1, p2}, La/b/p/x0;->e(I)Landroid/graphics/drawable/Drawable;

    move-result-object p2

    if-eqz p2, :cond_4

    .line 9
    iput-object p2, p0, La/b/p/z0;->e:Landroid/graphics/drawable/Drawable;

    invoke-virtual {p0}, La/b/p/z0;->y()V

    .line 10
    :cond_4
    iget-object p2, p0, La/b/p/z0;->g:Landroid/graphics/drawable/Drawable;

    if-nez p2, :cond_5

    iget-object p2, p0, La/b/p/z0;->q:Landroid/graphics/drawable/Drawable;

    if-eqz p2, :cond_5

    .line 11
    iput-object p2, p0, La/b/p/z0;->g:Landroid/graphics/drawable/Drawable;

    invoke-virtual {p0}, La/b/p/z0;->x()V

    .line 12
    :cond_5
    sget p2, La/b/j;->ActionBar_displayOptions:I

    invoke-virtual {p1, p2, v1}, La/b/p/x0;->h(II)I

    move-result p2

    invoke-virtual {p0, p2}, La/b/p/z0;->u(I)V

    sget p2, La/b/j;->ActionBar_customNavigationLayout:I

    invoke-virtual {p1, p2, v1}, La/b/p/x0;->j(II)I

    move-result p2

    if-eqz p2, :cond_8

    iget-object v2, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v2}, Landroid/view/ViewGroup;->getContext()Landroid/content/Context;

    move-result-object v2

    invoke-static {v2}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v2

    iget-object v3, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v2, p2, v3, v1}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    move-result-object p2

    .line 13
    iget-object v2, p0, La/b/p/z0;->d:Landroid/view/View;

    if-eqz v2, :cond_6

    iget v3, p0, La/b/p/z0;->b:I

    and-int/lit8 v3, v3, 0x10

    if-eqz v3, :cond_6

    iget-object v3, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v3, v2}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    :cond_6
    iput-object p2, p0, La/b/p/z0;->d:Landroid/view/View;

    if-eqz p2, :cond_7

    iget v2, p0, La/b/p/z0;->b:I

    and-int/lit8 v2, v2, 0x10

    if-eqz v2, :cond_7

    iget-object v2, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v2, p2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 14
    :cond_7
    iget p2, p0, La/b/p/z0;->b:I

    or-int/lit8 p2, p2, 0x10

    invoke-virtual {p0, p2}, La/b/p/z0;->u(I)V

    :cond_8
    sget p2, La/b/j;->ActionBar_height:I

    invoke-virtual {p1, p2, v1}, La/b/p/x0;->i(II)I

    move-result p2

    if-lez p2, :cond_9

    iget-object v2, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v2}, Landroid/view/ViewGroup;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v2

    iput p2, v2, Landroid/view/ViewGroup$LayoutParams;->height:I

    iget-object p2, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {p2, v2}, Landroid/view/ViewGroup;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    :cond_9
    sget p2, La/b/j;->ActionBar_contentInsetStart:I

    const/4 v2, -0x1

    invoke-virtual {p1, p2, v2}, La/b/p/x0;->c(II)I

    move-result p2

    sget v3, La/b/j;->ActionBar_contentInsetEnd:I

    invoke-virtual {p1, v3, v2}, La/b/p/x0;->c(II)I

    move-result v2

    if-gez p2, :cond_a

    if-ltz v2, :cond_b

    :cond_a
    iget-object v3, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-static {p2, v1}, Ljava/lang/Math;->max(II)I

    move-result p2

    invoke-static {v2, v1}, Ljava/lang/Math;->max(II)I

    move-result v2

    .line 15
    invoke-virtual {v3}, Landroidx/appcompat/widget/Toolbar;->d()V

    iget-object v3, v3, Landroidx/appcompat/widget/Toolbar;->u:La/b/p/p0;

    invoke-virtual {v3, p2, v2}, La/b/p/p0;->a(II)V

    .line 16
    :cond_b
    sget p2, La/b/j;->ActionBar_titleTextStyle:I

    invoke-virtual {p1, p2, v1}, La/b/p/x0;->j(II)I

    move-result p2

    if-eqz p2, :cond_c

    iget-object v2, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v2}, Landroid/view/ViewGroup;->getContext()Landroid/content/Context;

    move-result-object v3

    .line 17
    iput p2, v2, Landroidx/appcompat/widget/Toolbar;->m:I

    iget-object v2, v2, Landroidx/appcompat/widget/Toolbar;->c:Landroid/widget/TextView;

    if-eqz v2, :cond_c

    invoke-virtual {v2, v3, p2}, Landroid/widget/TextView;->setTextAppearance(Landroid/content/Context;I)V

    .line 18
    :cond_c
    sget p2, La/b/j;->ActionBar_subtitleTextStyle:I

    invoke-virtual {p1, p2, v1}, La/b/p/x0;->j(II)I

    move-result p2

    if-eqz p2, :cond_d

    iget-object v2, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v2}, Landroid/view/ViewGroup;->getContext()Landroid/content/Context;

    move-result-object v3

    .line 19
    iput p2, v2, Landroidx/appcompat/widget/Toolbar;->n:I

    iget-object v2, v2, Landroidx/appcompat/widget/Toolbar;->d:Landroid/widget/TextView;

    if-eqz v2, :cond_d

    invoke-virtual {v2, v3, p2}, Landroid/widget/TextView;->setTextAppearance(Landroid/content/Context;I)V

    .line 20
    :cond_d
    sget p2, La/b/j;->ActionBar_popupTheme:I

    invoke-virtual {p1, p2, v1}, La/b/p/x0;->j(II)I

    move-result p2

    if-eqz p2, :cond_10

    iget-object v1, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v1, p2}, Landroidx/appcompat/widget/Toolbar;->setPopupTheme(I)V

    goto :goto_2

    .line 21
    :cond_e
    iget-object p2, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {p2}, Landroidx/appcompat/widget/Toolbar;->getNavigationIcon()Landroid/graphics/drawable/Drawable;

    move-result-object p2

    if-eqz p2, :cond_f

    const/16 p2, 0xf

    iget-object v1, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v1}, Landroidx/appcompat/widget/Toolbar;->getNavigationIcon()Landroid/graphics/drawable/Drawable;

    move-result-object v1

    iput-object v1, p0, La/b/p/z0;->q:Landroid/graphics/drawable/Drawable;

    goto :goto_1

    :cond_f
    const/16 p2, 0xb

    .line 22
    :goto_1
    iput p2, p0, La/b/p/z0;->b:I

    .line 23
    :cond_10
    :goto_2
    iget-object p1, p1, La/b/p/x0;->b:Landroid/content/res/TypedArray;

    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    .line 24
    iget p1, p0, La/b/p/z0;->p:I

    if-ne v0, p1, :cond_11

    goto :goto_4

    :cond_11
    iput v0, p0, La/b/p/z0;->p:I

    iget-object p1, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {p1}, Landroidx/appcompat/widget/Toolbar;->getNavigationContentDescription()Ljava/lang/CharSequence;

    move-result-object p1

    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result p1

    if-eqz p1, :cond_13

    iget p1, p0, La/b/p/z0;->p:I

    if-nez p1, :cond_12

    goto :goto_3

    .line 25
    :cond_12
    invoke-virtual {p0}, La/b/p/z0;->t()Landroid/content/Context;

    move-result-object p2

    invoke-virtual {p2, p1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object v5

    .line 26
    :goto_3
    iput-object v5, p0, La/b/p/z0;->k:Ljava/lang/CharSequence;

    invoke-virtual {p0}, La/b/p/z0;->w()V

    .line 27
    :cond_13
    :goto_4
    iget-object p1, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {p1}, Landroidx/appcompat/widget/Toolbar;->getNavigationContentDescription()Ljava/lang/CharSequence;

    move-result-object p1

    iput-object p1, p0, La/b/p/z0;->k:Ljava/lang/CharSequence;

    iget-object p1, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    new-instance p2, La/b/p/y0;

    invoke-direct {p2, p0}, La/b/p/y0;-><init>(La/b/p/z0;)V

    invoke-virtual {p1, p2}, Landroidx/appcompat/widget/Toolbar;->setNavigationOnClickListener(Landroid/view/View$OnClickListener;)V

    return-void
.end method


# virtual methods
.method public a()Z
    .locals 1

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v0}, Landroidx/appcompat/widget/Toolbar;->u()Z

    move-result v0

    return v0
.end method

.method public b(Landroid/view/Menu;La/b/o/i/m$a;)V
    .locals 5

    iget-object v0, p0, La/b/p/z0;->n:La/b/p/c;

    const/4 v1, 0x0

    if-nez v0, :cond_1

    new-instance v0, La/b/p/c;

    iget-object v2, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v2}, Landroid/view/ViewGroup;->getContext()Landroid/content/Context;

    move-result-object v2

    invoke-direct {v0, v2}, La/b/p/c;-><init>(Landroid/content/Context;)V

    iput-object v0, p0, La/b/p/z0;->n:La/b/p/c;

    if-eqz v0, :cond_0

    goto :goto_0

    .line 1
    :cond_0
    throw v1

    .line 2
    :cond_1
    :goto_0
    iget-object v0, p0, La/b/p/z0;->n:La/b/p/c;

    .line 3
    iput-object p2, v0, La/b/o/i/b;->f:La/b/o/i/m$a;

    .line 4
    iget-object p2, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    check-cast p1, La/b/o/i/g;

    if-nez p1, :cond_2

    .line 5
    iget-object v2, p2, Landroidx/appcompat/widget/Toolbar;->b:Landroidx/appcompat/widget/ActionMenuView;

    if-nez v2, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {p2}, Landroidx/appcompat/widget/Toolbar;->f()V

    iget-object v2, p2, Landroidx/appcompat/widget/Toolbar;->b:Landroidx/appcompat/widget/ActionMenuView;

    .line 6
    iget-object v2, v2, Landroidx/appcompat/widget/ActionMenuView;->q:La/b/o/i/g;

    if-ne v2, p1, :cond_3

    goto :goto_2

    :cond_3
    if-eqz v2, :cond_4

    .line 7
    iget-object v3, p2, Landroidx/appcompat/widget/Toolbar;->K:La/b/p/c;

    invoke-virtual {v2, v3}, La/b/o/i/g;->u(La/b/o/i/m;)V

    iget-object v3, p2, Landroidx/appcompat/widget/Toolbar;->L:Landroidx/appcompat/widget/Toolbar$d;

    invoke-virtual {v2, v3}, La/b/o/i/g;->u(La/b/o/i/m;)V

    :cond_4
    iget-object v2, p2, Landroidx/appcompat/widget/Toolbar;->L:Landroidx/appcompat/widget/Toolbar$d;

    if-nez v2, :cond_5

    new-instance v2, Landroidx/appcompat/widget/Toolbar$d;

    invoke-direct {v2, p2}, Landroidx/appcompat/widget/Toolbar$d;-><init>(Landroidx/appcompat/widget/Toolbar;)V

    iput-object v2, p2, Landroidx/appcompat/widget/Toolbar;->L:Landroidx/appcompat/widget/Toolbar$d;

    :cond_5
    const/4 v2, 0x1

    .line 8
    iput-boolean v2, v0, La/b/p/c;->r:Z

    if-eqz p1, :cond_6

    .line 9
    iget-object v1, p2, Landroidx/appcompat/widget/Toolbar;->k:Landroid/content/Context;

    invoke-virtual {p1, v0, v1}, La/b/o/i/g;->b(La/b/o/i/m;Landroid/content/Context;)V

    iget-object v1, p2, Landroidx/appcompat/widget/Toolbar;->L:Landroidx/appcompat/widget/Toolbar$d;

    iget-object v2, p2, Landroidx/appcompat/widget/Toolbar;->k:Landroid/content/Context;

    invoke-virtual {p1, v1, v2}, La/b/o/i/g;->b(La/b/o/i/m;Landroid/content/Context;)V

    goto :goto_1

    :cond_6
    iget-object p1, p2, Landroidx/appcompat/widget/Toolbar;->k:Landroid/content/Context;

    invoke-virtual {v0, p1, v1}, La/b/p/c;->j(Landroid/content/Context;La/b/o/i/g;)V

    iget-object p1, p2, Landroidx/appcompat/widget/Toolbar;->L:Landroidx/appcompat/widget/Toolbar$d;

    .line 10
    iget-object v3, p1, Landroidx/appcompat/widget/Toolbar$d;->b:La/b/o/i/g;

    if-eqz v3, :cond_7

    iget-object v4, p1, Landroidx/appcompat/widget/Toolbar$d;->c:La/b/o/i/i;

    if-eqz v4, :cond_7

    invoke-virtual {v3, v4}, La/b/o/i/g;->d(La/b/o/i/i;)Z

    :cond_7
    iput-object v1, p1, Landroidx/appcompat/widget/Toolbar$d;->b:La/b/o/i/g;

    .line 11
    invoke-virtual {v0, v2}, La/b/p/c;->h(Z)V

    iget-object p1, p2, Landroidx/appcompat/widget/Toolbar;->L:Landroidx/appcompat/widget/Toolbar$d;

    invoke-virtual {p1, v2}, Landroidx/appcompat/widget/Toolbar$d;->h(Z)V

    :goto_1
    iget-object p1, p2, Landroidx/appcompat/widget/Toolbar;->b:Landroidx/appcompat/widget/ActionMenuView;

    iget v1, p2, Landroidx/appcompat/widget/Toolbar;->l:I

    invoke-virtual {p1, v1}, Landroidx/appcompat/widget/ActionMenuView;->setPopupTheme(I)V

    iget-object p1, p2, Landroidx/appcompat/widget/Toolbar;->b:Landroidx/appcompat/widget/ActionMenuView;

    invoke-virtual {p1, v0}, Landroidx/appcompat/widget/ActionMenuView;->setPresenter(La/b/p/c;)V

    iput-object v0, p2, Landroidx/appcompat/widget/Toolbar;->K:La/b/p/c;

    :goto_2
    return-void
.end method

.method public c()Z
    .locals 4

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    .line 1
    iget-object v0, v0, Landroidx/appcompat/widget/Toolbar;->b:Landroidx/appcompat/widget/ActionMenuView;

    const/4 v1, 0x1

    const/4 v2, 0x0

    if-eqz v0, :cond_3

    .line 2
    iget-object v0, v0, Landroidx/appcompat/widget/ActionMenuView;->u:La/b/p/c;

    if-eqz v0, :cond_2

    .line 3
    iget-object v3, v0, La/b/p/c;->w:La/b/p/c$c;

    if-nez v3, :cond_1

    invoke-virtual {v0}, La/b/p/c;->m()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    move v0, v2

    goto :goto_1

    :cond_1
    :goto_0
    move v0, v1

    :goto_1
    if-eqz v0, :cond_2

    move v0, v1

    goto :goto_2

    :cond_2
    move v0, v2

    :goto_2
    if-eqz v0, :cond_3

    goto :goto_3

    :cond_3
    move v1, v2

    :goto_3
    return v1
.end method

.method public collapseActionView()V
    .locals 1

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    .line 1
    iget-object v0, v0, Landroidx/appcompat/widget/Toolbar;->L:Landroidx/appcompat/widget/Toolbar$d;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    :cond_0
    iget-object v0, v0, Landroidx/appcompat/widget/Toolbar$d;->c:La/b/o/i/i;

    :goto_0
    if-eqz v0, :cond_1

    invoke-virtual {v0}, La/b/o/i/i;->collapseActionView()Z

    :cond_1
    return-void
.end method

.method public d()V
    .locals 1

    const/4 v0, 0x1

    iput-boolean v0, p0, La/b/p/z0;->m:Z

    return-void
.end method

.method public e()Z
    .locals 1

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v0}, Landroidx/appcompat/widget/Toolbar;->o()Z

    move-result v0

    return v0
.end method

.method public f()Z
    .locals 2

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    .line 1
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getVisibility()I

    move-result v1

    if-nez v1, :cond_0

    iget-object v0, v0, Landroidx/appcompat/widget/Toolbar;->b:Landroidx/appcompat/widget/ActionMenuView;

    if-eqz v0, :cond_0

    .line 2
    iget-boolean v0, v0, Landroidx/appcompat/widget/ActionMenuView;->t:Z

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public g()Z
    .locals 3

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    .line 1
    iget-object v0, v0, Landroidx/appcompat/widget/Toolbar;->b:Landroidx/appcompat/widget/ActionMenuView;

    const/4 v1, 0x1

    const/4 v2, 0x0

    if-eqz v0, :cond_1

    .line 2
    iget-object v0, v0, Landroidx/appcompat/widget/ActionMenuView;->u:La/b/p/c;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, La/b/p/c;->i()Z

    move-result v0

    if-eqz v0, :cond_0

    move v0, v1

    goto :goto_0

    :cond_0
    move v0, v2

    :goto_0
    if-eqz v0, :cond_1

    goto :goto_1

    :cond_1
    move v1, v2

    :goto_1
    return v1
.end method

.method public getTitle()Ljava/lang/CharSequence;
    .locals 1

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v0}, Landroidx/appcompat/widget/Toolbar;->getTitle()Ljava/lang/CharSequence;

    move-result-object v0

    return-object v0
.end method

.method public h()V
    .locals 1

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    .line 1
    iget-object v0, v0, Landroidx/appcompat/widget/Toolbar;->b:Landroidx/appcompat/widget/ActionMenuView;

    if-eqz v0, :cond_0

    .line 2
    iget-object v0, v0, Landroidx/appcompat/widget/ActionMenuView;->u:La/b/p/c;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, La/b/p/c;->e()Z

    :cond_0
    return-void
.end method

.method public i(IJ)La/f/j/p;
    .locals 2

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-static {v0}, La/f/j/k;->a(Landroid/view/View;)La/f/j/p;

    move-result-object v0

    if-nez p1, :cond_0

    const/high16 v1, 0x3f800000    # 1.0f

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    invoke-virtual {v0, v1}, La/f/j/p;->a(F)La/f/j/p;

    invoke-virtual {v0, p2, p3}, La/f/j/p;->c(J)La/f/j/p;

    new-instance p2, La/b/p/z0$a;

    invoke-direct {p2, p0, p1}, La/b/p/z0$a;-><init>(La/b/p/z0;I)V

    .line 1
    iget-object p1, v0, La/f/j/p;->a:Ljava/lang/ref/WeakReference;

    invoke-virtual {p1}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/view/View;

    if-eqz p1, :cond_1

    invoke-virtual {v0, p1, p2}, La/f/j/p;->e(Landroid/view/View;La/f/j/q;)V

    :cond_1
    return-object v0
.end method

.method public j()I
    .locals 1

    iget v0, p0, La/b/p/z0;->b:I

    return v0
.end method

.method public k(I)V
    .locals 1

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v0, p1}, Landroid/view/ViewGroup;->setVisibility(I)V

    return-void
.end method

.method public l()V
    .locals 2

    const-string v0, "ToolbarWidgetWrapper"

    const-string v1, "Progress display unsupported"

    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method

.method public m()Z
    .locals 1

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    .line 1
    iget-object v0, v0, Landroidx/appcompat/widget/Toolbar;->L:Landroidx/appcompat/widget/Toolbar$d;

    if-eqz v0, :cond_0

    iget-object v0, v0, Landroidx/appcompat/widget/Toolbar$d;->c:La/b/o/i/i;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public n(I)V
    .locals 1

    if-eqz p1, :cond_0

    invoke-virtual {p0}, La/b/p/z0;->t()Landroid/content/Context;

    move-result-object v0

    invoke-static {v0, p1}, La/b/l/a/a;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    move-result-object p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    .line 1
    :goto_0
    iput-object p1, p0, La/b/p/z0;->f:Landroid/graphics/drawable/Drawable;

    invoke-virtual {p0}, La/b/p/z0;->y()V

    return-void
.end method

.method public o(La/b/p/q0;)V
    .locals 1

    iget-object p1, p0, La/b/p/z0;->c:Landroid/view/View;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object p1

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    if-ne p1, v0, :cond_0

    iget-object p1, p0, La/b/p/z0;->c:Landroid/view/View;

    invoke-virtual {v0, p1}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    :cond_0
    const/4 p1, 0x0

    iput-object p1, p0, La/b/p/z0;->c:Landroid/view/View;

    return-void
.end method

.method public p()Landroid/view/ViewGroup;
    .locals 1

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    return-object v0
.end method

.method public q(Z)V
    .locals 0

    return-void
.end method

.method public r()V
    .locals 2

    const-string v0, "ToolbarWidgetWrapper"

    const-string v1, "Progress display unsupported"

    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method

.method public s(Z)V
    .locals 1

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v0, p1}, Landroidx/appcompat/widget/Toolbar;->setCollapsible(Z)V

    return-void
.end method

.method public setIcon(I)V
    .locals 1

    if-eqz p1, :cond_0

    invoke-virtual {p0}, La/b/p/z0;->t()Landroid/content/Context;

    move-result-object v0

    invoke-static {v0, p1}, La/b/l/a/a;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    move-result-object p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    .line 1
    :goto_0
    iput-object p1, p0, La/b/p/z0;->e:Landroid/graphics/drawable/Drawable;

    invoke-virtual {p0}, La/b/p/z0;->y()V

    return-void
.end method

.method public setIcon(Landroid/graphics/drawable/Drawable;)V
    .locals 0

    iput-object p1, p0, La/b/p/z0;->e:Landroid/graphics/drawable/Drawable;

    invoke-virtual {p0}, La/b/p/z0;->y()V

    return-void
.end method

.method public setWindowCallback(Landroid/view/Window$Callback;)V
    .locals 0

    iput-object p1, p0, La/b/p/z0;->l:Landroid/view/Window$Callback;

    return-void
.end method

.method public setWindowTitle(Ljava/lang/CharSequence;)V
    .locals 1

    iget-boolean v0, p0, La/b/p/z0;->h:Z

    if-nez v0, :cond_0

    .line 1
    iput-object p1, p0, La/b/p/z0;->i:Ljava/lang/CharSequence;

    iget v0, p0, La/b/p/z0;->b:I

    and-int/lit8 v0, v0, 0x8

    if-eqz v0, :cond_0

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v0, p1}, Landroidx/appcompat/widget/Toolbar;->setTitle(Ljava/lang/CharSequence;)V

    :cond_0
    return-void
.end method

.method public t()Landroid/content/Context;
    .locals 1

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v0}, Landroid/view/ViewGroup;->getContext()Landroid/content/Context;

    move-result-object v0

    return-object v0
.end method

.method public u(I)V
    .locals 3

    iget v0, p0, La/b/p/z0;->b:I

    xor-int/2addr v0, p1

    iput p1, p0, La/b/p/z0;->b:I

    if-eqz v0, :cond_6

    and-int/lit8 v1, v0, 0x4

    if-eqz v1, :cond_1

    and-int/lit8 v1, p1, 0x4

    if-eqz v1, :cond_0

    invoke-virtual {p0}, La/b/p/z0;->w()V

    :cond_0
    invoke-virtual {p0}, La/b/p/z0;->x()V

    :cond_1
    and-int/lit8 v1, v0, 0x3

    if-eqz v1, :cond_2

    invoke-virtual {p0}, La/b/p/z0;->y()V

    :cond_2
    and-int/lit8 v1, v0, 0x8

    if-eqz v1, :cond_4

    and-int/lit8 v1, p1, 0x8

    if-eqz v1, :cond_3

    iget-object v1, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    iget-object v2, p0, La/b/p/z0;->i:Ljava/lang/CharSequence;

    invoke-virtual {v1, v2}, Landroidx/appcompat/widget/Toolbar;->setTitle(Ljava/lang/CharSequence;)V

    iget-object v1, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    iget-object v2, p0, La/b/p/z0;->j:Ljava/lang/CharSequence;

    goto :goto_0

    :cond_3
    iget-object v1, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    const/4 v2, 0x0

    invoke-virtual {v1, v2}, Landroidx/appcompat/widget/Toolbar;->setTitle(Ljava/lang/CharSequence;)V

    iget-object v1, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    :goto_0
    invoke-virtual {v1, v2}, Landroidx/appcompat/widget/Toolbar;->setSubtitle(Ljava/lang/CharSequence;)V

    :cond_4
    and-int/lit8 v0, v0, 0x10

    if-eqz v0, :cond_6

    iget-object v0, p0, La/b/p/z0;->d:Landroid/view/View;

    if-eqz v0, :cond_6

    and-int/lit8 p1, p1, 0x10

    if-eqz p1, :cond_5

    iget-object p1, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {p1, v0}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    goto :goto_1

    :cond_5
    iget-object p1, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {p1, v0}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    :cond_6
    :goto_1
    return-void
.end method

.method public v()I
    .locals 1

    iget v0, p0, La/b/p/z0;->o:I

    return v0
.end method

.method public final w()V
    .locals 2

    iget v0, p0, La/b/p/z0;->b:I

    and-int/lit8 v0, v0, 0x4

    if-eqz v0, :cond_1

    iget-object v0, p0, La/b/p/z0;->k:Ljava/lang/CharSequence;

    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    iget v1, p0, La/b/p/z0;->p:I

    invoke-virtual {v0, v1}, Landroidx/appcompat/widget/Toolbar;->setNavigationContentDescription(I)V

    goto :goto_0

    :cond_0
    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    iget-object v1, p0, La/b/p/z0;->k:Ljava/lang/CharSequence;

    invoke-virtual {v0, v1}, Landroidx/appcompat/widget/Toolbar;->setNavigationContentDescription(Ljava/lang/CharSequence;)V

    :cond_1
    :goto_0
    return-void
.end method

.method public final x()V
    .locals 2

    iget v0, p0, La/b/p/z0;->b:I

    and-int/lit8 v0, v0, 0x4

    if-eqz v0, :cond_1

    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    iget-object v1, p0, La/b/p/z0;->g:Landroid/graphics/drawable/Drawable;

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object v1, p0, La/b/p/z0;->q:Landroid/graphics/drawable/Drawable;

    goto :goto_0

    :cond_1
    iget-object v0, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    const/4 v1, 0x0

    :goto_0
    invoke-virtual {v0, v1}, Landroidx/appcompat/widget/Toolbar;->setNavigationIcon(Landroid/graphics/drawable/Drawable;)V

    return-void
.end method

.method public final y()V
    .locals 2

    iget v0, p0, La/b/p/z0;->b:I

    and-int/lit8 v1, v0, 0x2

    if-eqz v1, :cond_1

    and-int/lit8 v0, v0, 0x1

    if-eqz v0, :cond_0

    iget-object v0, p0, La/b/p/z0;->f:Landroid/graphics/drawable/Drawable;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, La/b/p/z0;->e:Landroid/graphics/drawable/Drawable;

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    iget-object v1, p0, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v1, v0}, Landroidx/appcompat/widget/Toolbar;->setLogo(Landroid/graphics/drawable/Drawable;)V

    return-void
.end method
