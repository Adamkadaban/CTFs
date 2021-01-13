.class public La/b/p/w$b;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements La/b/p/w$f;
.implements Landroid/content/DialogInterface$OnClickListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/b/p/w;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "b"
.end annotation


# instance fields
.field public b:La/b/k/d;

.field public c:Landroid/widget/ListAdapter;

.field public d:Ljava/lang/CharSequence;

.field public final synthetic e:La/b/p/w;


# direct methods
.method public constructor <init>(La/b/p/w;)V
    .locals 0

    iput-object p1, p0, La/b/p/w$b;->e:La/b/p/w;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a()Z
    .locals 1

    iget-object v0, p0, La/b/p/w$b;->b:La/b/k/d;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroid/app/Dialog;->isShowing()Z

    move-result v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public b()Ljava/lang/CharSequence;
    .locals 1

    iget-object v0, p0, La/b/p/w$b;->d:Ljava/lang/CharSequence;

    return-object v0
.end method

.method public c(I)V
    .locals 1

    const-string p1, "AppCompatSpinner"

    const-string v0, "Cannot set horizontal offset for MODE_DIALOG, ignoring"

    invoke-static {p1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method

.method public d()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public dismiss()V
    .locals 1

    iget-object v0, p0, La/b/p/w$b;->b:La/b/k/d;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, La/b/k/n;->dismiss()V

    const/4 v0, 0x0

    iput-object v0, p0, La/b/p/w$b;->b:La/b/k/d;

    :cond_0
    return-void
.end method

.method public f(II)V
    .locals 4

    iget-object v0, p0, La/b/p/w$b;->c:Landroid/widget/ListAdapter;

    if-nez v0, :cond_0

    return-void

    :cond_0
    new-instance v0, La/b/k/d$a;

    iget-object v1, p0, La/b/p/w$b;->e:La/b/p/w;

    invoke-virtual {v1}, La/b/p/w;->getPopupContext()Landroid/content/Context;

    move-result-object v1

    invoke-direct {v0, v1}, La/b/k/d$a;-><init>(Landroid/content/Context;)V

    iget-object v1, p0, La/b/p/w$b;->d:Ljava/lang/CharSequence;

    if-eqz v1, :cond_1

    .line 1
    iget-object v2, v0, La/b/k/d$a;->a:Landroidx/appcompat/app/AlertController$b;

    iput-object v1, v2, Landroidx/appcompat/app/AlertController$b;->f:Ljava/lang/CharSequence;

    .line 2
    :cond_1
    iget-object v1, p0, La/b/p/w$b;->c:Landroid/widget/ListAdapter;

    iget-object v2, p0, La/b/p/w$b;->e:La/b/p/w;

    invoke-virtual {v2}, Landroid/widget/Spinner;->getSelectedItemPosition()I

    move-result v2

    .line 3
    iget-object v3, v0, La/b/k/d$a;->a:Landroidx/appcompat/app/AlertController$b;

    iput-object v1, v3, Landroidx/appcompat/app/AlertController$b;->l:Landroid/widget/ListAdapter;

    iput-object p0, v3, Landroidx/appcompat/app/AlertController$b;->m:Landroid/content/DialogInterface$OnClickListener;

    iput v2, v3, Landroidx/appcompat/app/AlertController$b;->p:I

    const/4 v1, 0x1

    iput-boolean v1, v3, Landroidx/appcompat/app/AlertController$b;->o:Z

    .line 4
    invoke-virtual {v0}, La/b/k/d$a;->a()La/b/k/d;

    move-result-object v0

    iput-object v0, p0, La/b/p/w$b;->b:La/b/k/d;

    .line 5
    iget-object v0, v0, La/b/k/d;->d:Landroidx/appcompat/app/AlertController;

    .line 6
    iget-object v0, v0, Landroidx/appcompat/app/AlertController;->g:Landroid/widget/ListView;

    .line 7
    invoke-virtual {v0, p1}, Landroid/widget/ListView;->setTextDirection(I)V

    invoke-virtual {v0, p2}, Landroid/widget/ListView;->setTextAlignment(I)V

    iget-object p1, p0, La/b/p/w$b;->b:La/b/k/d;

    invoke-virtual {p1}, Landroid/app/Dialog;->show()V

    return-void
.end method

.method public h(Ljava/lang/CharSequence;)V
    .locals 0

    iput-object p1, p0, La/b/p/w$b;->d:Ljava/lang/CharSequence;

    return-void
.end method

.method public j()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public l(Landroid/graphics/drawable/Drawable;)V
    .locals 1

    const-string p1, "AppCompatSpinner"

    const-string v0, "Cannot set popup background for MODE_DIALOG, ignoring"

    invoke-static {p1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method

.method public m(I)V
    .locals 1

    const-string p1, "AppCompatSpinner"

    const-string v0, "Cannot set vertical offset for MODE_DIALOG, ignoring"

    invoke-static {p1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method

.method public n()Landroid/graphics/drawable/Drawable;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public o(Landroid/widget/ListAdapter;)V
    .locals 0

    iput-object p1, p0, La/b/p/w$b;->c:Landroid/widget/ListAdapter;

    return-void
.end method

.method public onClick(Landroid/content/DialogInterface;I)V
    .locals 3

    iget-object p1, p0, La/b/p/w$b;->e:La/b/p/w;

    invoke-virtual {p1, p2}, Landroid/widget/Spinner;->setSelection(I)V

    iget-object p1, p0, La/b/p/w$b;->e:La/b/p/w;

    invoke-virtual {p1}, Landroid/widget/Spinner;->getOnItemClickListener()Landroid/widget/AdapterView$OnItemClickListener;

    move-result-object p1

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    iget-object p1, p0, La/b/p/w$b;->e:La/b/p/w;

    iget-object v1, p0, La/b/p/w$b;->c:Landroid/widget/ListAdapter;

    invoke-interface {v1, p2}, Landroid/widget/ListAdapter;->getItemId(I)J

    move-result-wide v1

    invoke-virtual {p1, v0, p2, v1, v2}, Landroid/widget/Spinner;->performItemClick(Landroid/view/View;IJ)Z

    .line 1
    :cond_0
    iget-object p1, p0, La/b/p/w$b;->b:La/b/k/d;

    if-eqz p1, :cond_1

    invoke-virtual {p1}, La/b/k/n;->dismiss()V

    iput-object v0, p0, La/b/p/w$b;->b:La/b/k/d;

    :cond_1
    return-void
.end method

.method public p(I)V
    .locals 1

    const-string p1, "AppCompatSpinner"

    const-string v0, "Cannot set horizontal (original) offset for MODE_DIALOG, ignoring"

    invoke-static {p1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method
