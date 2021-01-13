.class public La/b/k/d$a;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/b/k/d;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "a"
.end annotation


# instance fields
.field public final a:Landroidx/appcompat/app/AlertController$b;

.field public final b:I


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 4

    const/4 v0, 0x0

    invoke-static {p1, v0}, La/b/k/d;->d(Landroid/content/Context;I)I

    move-result v0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v1, Landroidx/appcompat/app/AlertController$b;

    new-instance v2, Landroid/view/ContextThemeWrapper;

    invoke-static {p1, v0}, La/b/k/d;->d(Landroid/content/Context;I)I

    move-result v3

    invoke-direct {v2, p1, v3}, Landroid/view/ContextThemeWrapper;-><init>(Landroid/content/Context;I)V

    invoke-direct {v1, v2}, Landroidx/appcompat/app/AlertController$b;-><init>(Landroid/content/Context;)V

    iput-object v1, p0, La/b/k/d$a;->a:Landroidx/appcompat/app/AlertController$b;

    iput v0, p0, La/b/k/d$a;->b:I

    return-void
.end method


# virtual methods
.method public a()La/b/k/d;
    .locals 10

    new-instance v0, La/b/k/d;

    iget-object v1, p0, La/b/k/d$a;->a:Landroidx/appcompat/app/AlertController$b;

    iget-object v1, v1, Landroidx/appcompat/app/AlertController$b;->a:Landroid/content/Context;

    iget v2, p0, La/b/k/d$a;->b:I

    invoke-direct {v0, v1, v2}, La/b/k/d;-><init>(Landroid/content/Context;I)V

    iget-object v1, p0, La/b/k/d$a;->a:Landroidx/appcompat/app/AlertController$b;

    iget-object v2, v0, La/b/k/d;->d:Landroidx/appcompat/app/AlertController;

    .line 1
    iget-object v3, v1, Landroidx/appcompat/app/AlertController$b;->g:Landroid/view/View;

    const/4 v4, 0x0

    const/4 v5, 0x1

    if-eqz v3, :cond_0

    .line 2
    iput-object v3, v2, Landroidx/appcompat/app/AlertController;->G:Landroid/view/View;

    goto :goto_0

    .line 3
    :cond_0
    iget-object v3, v1, Landroidx/appcompat/app/AlertController$b;->f:Ljava/lang/CharSequence;

    if-eqz v3, :cond_1

    .line 4
    iput-object v3, v2, Landroidx/appcompat/app/AlertController;->e:Ljava/lang/CharSequence;

    iget-object v6, v2, Landroidx/appcompat/app/AlertController;->E:Landroid/widget/TextView;

    if-eqz v6, :cond_1

    invoke-virtual {v6, v3}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 5
    :cond_1
    iget-object v3, v1, Landroidx/appcompat/app/AlertController$b;->d:Landroid/graphics/drawable/Drawable;

    if-eqz v3, :cond_2

    .line 6
    iput-object v3, v2, Landroidx/appcompat/app/AlertController;->C:Landroid/graphics/drawable/Drawable;

    const/4 v6, 0x0

    iput v6, v2, Landroidx/appcompat/app/AlertController;->B:I

    iget-object v7, v2, Landroidx/appcompat/app/AlertController;->D:Landroid/widget/ImageView;

    if-eqz v7, :cond_2

    invoke-virtual {v7, v6}, Landroid/widget/ImageView;->setVisibility(I)V

    iget-object v6, v2, Landroidx/appcompat/app/AlertController;->D:Landroid/widget/ImageView;

    invoke-virtual {v6, v3}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 7
    :cond_2
    iget v3, v1, Landroidx/appcompat/app/AlertController$b;->c:I

    if-eqz v3, :cond_3

    invoke-virtual {v2, v3}, Landroidx/appcompat/app/AlertController;->e(I)V

    :cond_3
    iget v3, v1, Landroidx/appcompat/app/AlertController$b;->e:I

    if-eqz v3, :cond_5

    if-eqz v2, :cond_4

    .line 8
    new-instance v6, Landroid/util/TypedValue;

    invoke-direct {v6}, Landroid/util/TypedValue;-><init>()V

    iget-object v7, v2, Landroidx/appcompat/app/AlertController;->a:Landroid/content/Context;

    invoke-virtual {v7}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v7

    invoke-virtual {v7, v3, v6, v5}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    iget v3, v6, Landroid/util/TypedValue;->resourceId:I

    .line 9
    invoke-virtual {v2, v3}, Landroidx/appcompat/app/AlertController;->e(I)V

    goto :goto_0

    .line 10
    :cond_4
    throw v4

    .line 11
    :cond_5
    :goto_0
    iget-object v3, v1, Landroidx/appcompat/app/AlertController$b;->l:Landroid/widget/ListAdapter;

    if-eqz v3, :cond_a

    .line 12
    iget-object v3, v1, Landroidx/appcompat/app/AlertController$b;->b:Landroid/view/LayoutInflater;

    iget v6, v2, Landroidx/appcompat/app/AlertController;->L:I

    invoke-virtual {v3, v6, v4}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    move-result-object v3

    check-cast v3, Landroidx/appcompat/app/AlertController$RecycleListView;

    iget-boolean v6, v1, Landroidx/appcompat/app/AlertController$b;->o:Z

    if-eqz v6, :cond_6

    iget v6, v2, Landroidx/appcompat/app/AlertController;->N:I

    goto :goto_1

    :cond_6
    iget v6, v2, Landroidx/appcompat/app/AlertController;->O:I

    :goto_1
    iget-object v7, v1, Landroidx/appcompat/app/AlertController$b;->l:Landroid/widget/ListAdapter;

    if-eqz v7, :cond_7

    goto :goto_2

    :cond_7
    new-instance v7, Landroidx/appcompat/app/AlertController$d;

    iget-object v8, v1, Landroidx/appcompat/app/AlertController$b;->a:Landroid/content/Context;

    const v9, 0x1020014

    invoke-direct {v7, v8, v6, v9, v4}, Landroidx/appcompat/app/AlertController$d;-><init>(Landroid/content/Context;II[Ljava/lang/CharSequence;)V

    :goto_2
    iput-object v7, v2, Landroidx/appcompat/app/AlertController;->H:Landroid/widget/ListAdapter;

    iget v4, v1, Landroidx/appcompat/app/AlertController$b;->p:I

    iput v4, v2, Landroidx/appcompat/app/AlertController;->I:I

    iget-object v4, v1, Landroidx/appcompat/app/AlertController$b;->m:Landroid/content/DialogInterface$OnClickListener;

    if-eqz v4, :cond_8

    new-instance v4, La/b/k/c;

    invoke-direct {v4, v1, v2}, La/b/k/c;-><init>(Landroidx/appcompat/app/AlertController$b;Landroidx/appcompat/app/AlertController;)V

    invoke-virtual {v3, v4}, Landroid/widget/ListView;->setOnItemClickListener(Landroid/widget/AdapterView$OnItemClickListener;)V

    :cond_8
    iget-boolean v1, v1, Landroidx/appcompat/app/AlertController$b;->o:Z

    if-eqz v1, :cond_9

    invoke-virtual {v3, v5}, Landroid/widget/ListView;->setChoiceMode(I)V

    :cond_9
    iput-object v3, v2, Landroidx/appcompat/app/AlertController;->g:Landroid/widget/ListView;

    .line 13
    :cond_a
    iget-object v1, p0, La/b/k/d$a;->a:Landroidx/appcompat/app/AlertController$b;

    iget-boolean v1, v1, Landroidx/appcompat/app/AlertController$b;->h:Z

    invoke-virtual {v0, v1}, Landroid/app/Dialog;->setCancelable(Z)V

    iget-object v1, p0, La/b/k/d$a;->a:Landroidx/appcompat/app/AlertController$b;

    iget-boolean v1, v1, Landroidx/appcompat/app/AlertController$b;->h:Z

    if-eqz v1, :cond_b

    invoke-virtual {v0, v5}, Landroid/app/Dialog;->setCanceledOnTouchOutside(Z)V

    :cond_b
    iget-object v1, p0, La/b/k/d$a;->a:Landroidx/appcompat/app/AlertController$b;

    iget-object v1, v1, Landroidx/appcompat/app/AlertController$b;->i:Landroid/content/DialogInterface$OnCancelListener;

    invoke-virtual {v0, v1}, Landroid/app/Dialog;->setOnCancelListener(Landroid/content/DialogInterface$OnCancelListener;)V

    iget-object v1, p0, La/b/k/d$a;->a:Landroidx/appcompat/app/AlertController$b;

    iget-object v1, v1, Landroidx/appcompat/app/AlertController$b;->j:Landroid/content/DialogInterface$OnDismissListener;

    invoke-virtual {v0, v1}, Landroid/app/Dialog;->setOnDismissListener(Landroid/content/DialogInterface$OnDismissListener;)V

    iget-object v1, p0, La/b/k/d$a;->a:Landroidx/appcompat/app/AlertController$b;

    iget-object v1, v1, Landroidx/appcompat/app/AlertController$b;->k:Landroid/content/DialogInterface$OnKeyListener;

    if-eqz v1, :cond_c

    invoke-virtual {v0, v1}, Landroid/app/Dialog;->setOnKeyListener(Landroid/content/DialogInterface$OnKeyListener;)V

    :cond_c
    return-object v0
.end method
