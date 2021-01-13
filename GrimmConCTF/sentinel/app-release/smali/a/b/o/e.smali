.class public La/b/o/e;
.super Landroid/view/ActionMode;
.source ""


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/b/o/e$a;
    }
.end annotation


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:La/b/o/a;


# direct methods
.method public constructor <init>(Landroid/content/Context;La/b/o/a;)V
    .locals 0

    invoke-direct {p0}, Landroid/view/ActionMode;-><init>()V

    iput-object p1, p0, La/b/o/e;->a:Landroid/content/Context;

    iput-object p2, p0, La/b/o/e;->b:La/b/o/a;

    return-void
.end method


# virtual methods
.method public finish()V
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    invoke-virtual {v0}, La/b/o/a;->c()V

    return-void
.end method

.method public getCustomView()Landroid/view/View;
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    invoke-virtual {v0}, La/b/o/a;->d()Landroid/view/View;

    move-result-object v0

    return-object v0
.end method

.method public getMenu()Landroid/view/Menu;
    .locals 3

    new-instance v0, La/b/o/i/o;

    iget-object v1, p0, La/b/o/e;->a:Landroid/content/Context;

    iget-object v2, p0, La/b/o/e;->b:La/b/o/a;

    invoke-virtual {v2}, La/b/o/a;->e()Landroid/view/Menu;

    move-result-object v2

    check-cast v2, La/f/f/a/a;

    invoke-direct {v0, v1, v2}, La/b/o/i/o;-><init>(Landroid/content/Context;La/f/f/a/a;)V

    return-object v0
.end method

.method public getMenuInflater()Landroid/view/MenuInflater;
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    invoke-virtual {v0}, La/b/o/a;->f()Landroid/view/MenuInflater;

    move-result-object v0

    return-object v0
.end method

.method public getSubtitle()Ljava/lang/CharSequence;
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    invoke-virtual {v0}, La/b/o/a;->g()Ljava/lang/CharSequence;

    move-result-object v0

    return-object v0
.end method

.method public getTag()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    .line 1
    iget-object v0, v0, La/b/o/a;->b:Ljava/lang/Object;

    return-object v0
.end method

.method public getTitle()Ljava/lang/CharSequence;
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    invoke-virtual {v0}, La/b/o/a;->h()Ljava/lang/CharSequence;

    move-result-object v0

    return-object v0
.end method

.method public getTitleOptionalHint()Z
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    .line 1
    iget-boolean v0, v0, La/b/o/a;->c:Z

    return v0
.end method

.method public invalidate()V
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    invoke-virtual {v0}, La/b/o/a;->i()V

    return-void
.end method

.method public isTitleOptional()Z
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    invoke-virtual {v0}, La/b/o/a;->j()Z

    move-result v0

    return v0
.end method

.method public setCustomView(Landroid/view/View;)V
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    invoke-virtual {v0, p1}, La/b/o/a;->k(Landroid/view/View;)V

    return-void
.end method

.method public setSubtitle(I)V
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    invoke-virtual {v0, p1}, La/b/o/a;->l(I)V

    return-void
.end method

.method public setSubtitle(Ljava/lang/CharSequence;)V
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    invoke-virtual {v0, p1}, La/b/o/a;->m(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public setTag(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    .line 1
    iput-object p1, v0, La/b/o/a;->b:Ljava/lang/Object;

    return-void
.end method

.method public setTitle(I)V
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    invoke-virtual {v0, p1}, La/b/o/a;->n(I)V

    return-void
.end method

.method public setTitle(Ljava/lang/CharSequence;)V
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    invoke-virtual {v0, p1}, La/b/o/a;->o(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public setTitleOptionalHint(Z)V
    .locals 1

    iget-object v0, p0, La/b/o/e;->b:La/b/o/a;

    invoke-virtual {v0, p1}, La/b/o/a;->p(Z)V

    return-void
.end method
