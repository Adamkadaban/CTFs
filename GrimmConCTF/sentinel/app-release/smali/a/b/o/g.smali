.class public La/b/o/g;
.super Ljava/lang/Object;
.source ""


# instance fields
.field public final a:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "La/f/j/p;",
            ">;"
        }
    .end annotation
.end field

.field public b:J

.field public c:Landroid/view/animation/Interpolator;

.field public d:La/f/j/q;

.field public e:Z

.field public final f:La/f/j/r;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-wide/16 v0, -0x1

    iput-wide v0, p0, La/b/o/g;->b:J

    new-instance v0, La/b/o/g$a;

    invoke-direct {v0, p0}, La/b/o/g$a;-><init>(La/b/o/g;)V

    iput-object v0, p0, La/b/o/g;->f:La/f/j/r;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, La/b/o/g;->a:Ljava/util/ArrayList;

    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    iget-boolean v0, p0, La/b/o/g;->e:Z

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget-object v0, p0, La/b/o/g;->a:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/f/j/p;

    invoke-virtual {v1}, La/f/j/p;->b()V

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    iput-boolean v0, p0, La/b/o/g;->e:Z

    return-void
.end method

.method public b()V
    .locals 6

    iget-boolean v0, p0, La/b/o/g;->e:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    iget-object v0, p0, La/b/o/g;->a:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_1
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_5

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/f/j/p;

    iget-wide v2, p0, La/b/o/g;->b:J

    const-wide/16 v4, 0x0

    cmp-long v4, v2, v4

    if-ltz v4, :cond_2

    invoke-virtual {v1, v2, v3}, La/f/j/p;->c(J)La/f/j/p;

    :cond_2
    iget-object v2, p0, La/b/o/g;->c:Landroid/view/animation/Interpolator;

    if-eqz v2, :cond_3

    .line 1
    iget-object v3, v1, La/f/j/p;->a:Ljava/lang/ref/WeakReference;

    invoke-virtual {v3}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/view/View;

    if-eqz v3, :cond_3

    invoke-virtual {v3}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    move-result-object v3

    invoke-virtual {v3, v2}, Landroid/view/ViewPropertyAnimator;->setInterpolator(Landroid/animation/TimeInterpolator;)Landroid/view/ViewPropertyAnimator;

    .line 2
    :cond_3
    iget-object v2, p0, La/b/o/g;->d:La/f/j/q;

    if-eqz v2, :cond_4

    iget-object v2, p0, La/b/o/g;->f:La/f/j/r;

    invoke-virtual {v1, v2}, La/f/j/p;->d(La/f/j/q;)La/f/j/p;

    .line 3
    :cond_4
    iget-object v1, v1, La/f/j/p;->a:Ljava/lang/ref/WeakReference;

    invoke-virtual {v1}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/view/View;

    if-eqz v1, :cond_1

    invoke-virtual {v1}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    move-result-object v1

    invoke-virtual {v1}, Landroid/view/ViewPropertyAnimator;->start()V

    goto :goto_0

    :cond_5
    const/4 v0, 0x1

    .line 4
    iput-boolean v0, p0, La/b/o/g;->e:Z

    return-void
.end method
