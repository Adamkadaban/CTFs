.class public La/b/k/n;
.super Landroid/app/Dialog;
.source ""

# interfaces
.implements La/b/k/f;


# instance fields
.field public b:La/b/k/g;

.field public final c:La/f/j/d$a;


# direct methods
.method public constructor <init>(Landroid/content/Context;I)V
    .locals 4

    const/4 v0, 0x1

    if-nez p2, :cond_0

    .line 1
    new-instance v1, Landroid/util/TypedValue;

    invoke-direct {v1}, Landroid/util/TypedValue;-><init>()V

    invoke-virtual {p1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v2

    sget v3, La/b/a;->dialogTheme:I

    invoke-virtual {v2, v3, v1, v0}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    iget v1, v1, Landroid/util/TypedValue;->resourceId:I

    goto :goto_0

    :cond_0
    move v1, p2

    .line 2
    :goto_0
    invoke-direct {p0, p1, v1}, Landroid/app/Dialog;-><init>(Landroid/content/Context;I)V

    new-instance v1, La/b/k/n$a;

    invoke-direct {v1, p0}, La/b/k/n$a;-><init>(La/b/k/n;)V

    iput-object v1, p0, La/b/k/n;->c:La/f/j/d$a;

    invoke-virtual {p0}, La/b/k/n;->a()La/b/k/g;

    move-result-object v1

    if-nez p2, :cond_1

    .line 3
    new-instance p2, Landroid/util/TypedValue;

    invoke-direct {p2}, Landroid/util/TypedValue;-><init>()V

    invoke-virtual {p1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object p1

    sget v2, La/b/a;->dialogTheme:I

    invoke-virtual {p1, v2, p2, v0}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    iget p2, p2, Landroid/util/TypedValue;->resourceId:I

    .line 4
    :cond_1
    move-object p1, v1

    check-cast p1, La/b/k/h;

    .line 5
    iput p2, p1, La/b/k/h;->O:I

    const/4 p1, 0x0

    .line 6
    invoke-virtual {v1, p1}, La/b/k/g;->h(Landroid/os/Bundle;)V

    return-void
.end method


# virtual methods
.method public a()La/b/k/g;
    .locals 1

    iget-object v0, p0, La/b/k/n;->b:La/b/k/g;

    if-nez v0, :cond_0

    invoke-static {p0, p0}, La/b/k/g;->e(Landroid/app/Dialog;La/b/k/f;)La/b/k/g;

    move-result-object v0

    iput-object v0, p0, La/b/k/n;->b:La/b/k/g;

    :cond_0
    iget-object v0, p0, La/b/k/n;->b:La/b/k/g;

    return-object v0
.end method

.method public addContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 1

    invoke-virtual {p0}, La/b/k/n;->a()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0, p1, p2}, La/b/k/g;->c(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    return-void
.end method

.method public b(La/b/o/a;)V
    .locals 0

    return-void
.end method

.method public c(Landroid/view/KeyEvent;)Z
    .locals 0

    invoke-super {p0, p1}, Landroid/app/Dialog;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    move-result p1

    return p1
.end method

.method public dismiss()V
    .locals 1

    invoke-super {p0}, Landroid/app/Dialog;->dismiss()V

    invoke-virtual {p0}, La/b/k/n;->a()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0}, La/b/k/g;->i()V

    return-void
.end method

.method public dispatchKeyEvent(Landroid/view/KeyEvent;)Z
    .locals 2

    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    move-result-object v0

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object v0

    iget-object v1, p0, La/b/k/n;->c:La/f/j/d$a;

    invoke-static {v1, v0, p0, p1}, La/f/j/d;->a(La/f/j/d$a;Landroid/view/View;Landroid/view/Window$Callback;Landroid/view/KeyEvent;)Z

    move-result p1

    return p1
.end method

.method public f(La/b/o/a;)V
    .locals 0

    return-void
.end method

.method public findViewById(I)Landroid/view/View;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Landroid/view/View;",
            ">(I)TT;"
        }
    .end annotation

    invoke-virtual {p0}, La/b/k/n;->a()La/b/k/g;

    move-result-object v0

    check-cast v0, La/b/k/h;

    .line 1
    invoke-virtual {v0}, La/b/k/h;->z()V

    iget-object v0, v0, La/b/k/h;->f:Landroid/view/Window;

    invoke-virtual {v0, p1}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    move-result-object p1

    return-object p1
.end method

.method public g(La/b/o/a$a;)La/b/o/a;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public invalidateOptionsMenu()V
    .locals 1

    invoke-virtual {p0}, La/b/k/n;->a()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0}, La/b/k/g;->g()V

    return-void
.end method

.method public onCreate(Landroid/os/Bundle;)V
    .locals 1

    invoke-virtual {p0}, La/b/k/n;->a()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0}, La/b/k/g;->f()V

    invoke-super {p0, p1}, Landroid/app/Dialog;->onCreate(Landroid/os/Bundle;)V

    invoke-virtual {p0}, La/b/k/n;->a()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0, p1}, La/b/k/g;->h(Landroid/os/Bundle;)V

    return-void
.end method

.method public onStop()V
    .locals 2

    invoke-super {p0}, Landroid/app/Dialog;->onStop()V

    invoke-virtual {p0}, La/b/k/n;->a()La/b/k/g;

    move-result-object v0

    check-cast v0, La/b/k/h;

    const/4 v1, 0x0

    .line 1
    iput-boolean v1, v0, La/b/k/h;->L:Z

    .line 2
    invoke-virtual {v0}, La/b/k/h;->F()V

    iget-object v0, v0, La/b/k/h;->i:La/b/k/a;

    if-eqz v0, :cond_0

    .line 3
    invoke-virtual {v0, v1}, La/b/k/a;->h(Z)V

    :cond_0
    return-void
.end method

.method public setContentView(I)V
    .locals 1

    invoke-virtual {p0}, La/b/k/n;->a()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0, p1}, La/b/k/g;->l(I)V

    return-void
.end method

.method public setContentView(Landroid/view/View;)V
    .locals 1

    invoke-virtual {p0}, La/b/k/n;->a()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0, p1}, La/b/k/g;->m(Landroid/view/View;)V

    return-void
.end method

.method public setContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 1

    invoke-virtual {p0}, La/b/k/n;->a()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0, p1, p2}, La/b/k/g;->n(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    return-void
.end method

.method public setTitle(I)V
    .locals 2

    invoke-super {p0, p1}, Landroid/app/Dialog;->setTitle(I)V

    invoke-virtual {p0}, La/b/k/n;->a()La/b/k/g;

    move-result-object v0

    invoke-virtual {p0}, Landroid/app/Dialog;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-virtual {v1, p1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, La/b/k/g;->o(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public setTitle(Ljava/lang/CharSequence;)V
    .locals 1

    invoke-super {p0, p1}, Landroid/app/Dialog;->setTitle(Ljava/lang/CharSequence;)V

    invoke-virtual {p0}, La/b/k/n;->a()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0, p1}, La/b/k/g;->o(Ljava/lang/CharSequence;)V

    return-void
.end method
