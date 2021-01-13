.class public La/b/o/i/d$a;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/b/o/i/d;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic b:La/b/o/i/d;


# direct methods
.method public constructor <init>(La/b/o/i/d;)V
    .locals 0

    iput-object p1, p0, La/b/o/i/d$a;->b:La/b/o/i/d;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onGlobalLayout()V
    .locals 2

    iget-object v0, p0, La/b/o/i/d$a;->b:La/b/o/i/d;

    invoke-virtual {v0}, La/b/o/i/d;->a()Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object v0, p0, La/b/o/i/d$a;->b:La/b/o/i/d;

    iget-object v0, v0, La/b/o/i/d;->j:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    if-lez v0, :cond_2

    iget-object v0, p0, La/b/o/i/d$a;->b:La/b/o/i/d;

    iget-object v0, v0, La/b/o/i/d;->j:Ljava/util/List;

    const/4 v1, 0x0

    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/b/o/i/d$d;

    iget-object v0, v0, La/b/o/i/d$d;->a:La/b/p/m0;

    .line 1
    iget-boolean v0, v0, La/b/p/k0;->B:Z

    if-nez v0, :cond_2

    .line 2
    iget-object v0, p0, La/b/o/i/d$a;->b:La/b/o/i/d;

    iget-object v0, v0, La/b/o/i/d;->q:Landroid/view/View;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Landroid/view/View;->isShown()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    iget-object v0, p0, La/b/o/i/d$a;->b:La/b/o/i/d;

    iget-object v0, v0, La/b/o/i/d;->j:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/b/o/i/d$d;

    iget-object v1, v1, La/b/o/i/d$d;->a:La/b/p/m0;

    invoke-virtual {v1}, La/b/p/k0;->i()V

    goto :goto_0

    :cond_1
    :goto_1
    iget-object v0, p0, La/b/o/i/d$a;->b:La/b/o/i/d;

    invoke-virtual {v0}, La/b/o/i/d;->dismiss()V

    :cond_2
    return-void
.end method
