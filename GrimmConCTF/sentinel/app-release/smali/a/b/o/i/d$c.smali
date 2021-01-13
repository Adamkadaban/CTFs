.class public La/b/o/i/d$c;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements La/b/p/l0;


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

    iput-object p1, p0, La/b/o/i/d$c;->b:La/b/o/i/d;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public g(La/b/o/i/g;Landroid/view/MenuItem;)V
    .locals 5

    iget-object v0, p0, La/b/o/i/d$c;->b:La/b/o/i/d;

    iget-object v0, v0, La/b/o/i/d;->h:Landroid/os/Handler;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    iget-object v0, p0, La/b/o/i/d$c;->b:La/b/o/i/d;

    iget-object v0, v0, La/b/o/i/d;->j:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    const/4 v2, 0x0

    :goto_0
    const/4 v3, -0x1

    if-ge v2, v0, :cond_1

    iget-object v4, p0, La/b/o/i/d$c;->b:La/b/o/i/d;

    iget-object v4, v4, La/b/o/i/d;->j:Ljava/util/List;

    invoke-interface {v4, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, La/b/o/i/d$d;

    iget-object v4, v4, La/b/o/i/d$d;->b:La/b/o/i/g;

    if-ne p1, v4, :cond_0

    goto :goto_1

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    move v2, v3

    :goto_1
    if-ne v2, v3, :cond_2

    return-void

    :cond_2
    add-int/lit8 v2, v2, 0x1

    iget-object v0, p0, La/b/o/i/d$c;->b:La/b/o/i/d;

    iget-object v0, v0, La/b/o/i/d;->j:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    if-ge v2, v0, :cond_3

    iget-object v0, p0, La/b/o/i/d$c;->b:La/b/o/i/d;

    iget-object v0, v0, La/b/o/i/d;->j:Ljava/util/List;

    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, La/b/o/i/d$d;

    :cond_3
    new-instance v0, La/b/o/i/d$c$a;

    invoke-direct {v0, p0, v1, p2, p1}, La/b/o/i/d$c$a;-><init>(La/b/o/i/d$c;La/b/o/i/d$d;Landroid/view/MenuItem;La/b/o/i/g;)V

    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    move-result-wide v1

    const-wide/16 v3, 0xc8

    add-long/2addr v1, v3

    iget-object p2, p0, La/b/o/i/d$c;->b:La/b/o/i/d;

    iget-object p2, p2, La/b/o/i/d;->h:Landroid/os/Handler;

    invoke-virtual {p2, v0, p1, v1, v2}, Landroid/os/Handler;->postAtTime(Ljava/lang/Runnable;Ljava/lang/Object;J)Z

    return-void
.end method

.method public k(La/b/o/i/g;Landroid/view/MenuItem;)V
    .locals 0

    iget-object p2, p0, La/b/o/i/d$c;->b:La/b/o/i/d;

    iget-object p2, p2, La/b/o/i/d;->h:Landroid/os/Handler;

    invoke-virtual {p2, p1}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    return-void
.end method
