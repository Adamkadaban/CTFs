.class public abstract La/b/k/g;
.super Ljava/lang/Object;
.source ""


# static fields
.field public static final b:La/d/c;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "La/d/c<",
            "Ljava/lang/ref/WeakReference<",
            "La/b/k/g;",
            ">;>;"
        }
    .end annotation
.end field

.field public static final c:Ljava/lang/Object;


# direct methods
.method public static constructor <clinit>()V
    .locals 1

    new-instance v0, La/d/c;

    invoke-direct {v0}, La/d/c;-><init>()V

    sput-object v0, La/b/k/g;->b:La/d/c;

    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, La/b/k/g;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static d(Landroid/app/Activity;La/b/k/f;)La/b/k/g;
    .locals 2

    new-instance v0, La/b/k/h;

    const/4 v1, 0x0

    .line 1
    invoke-direct {v0, p0, v1, p1, p0}, La/b/k/h;-><init>(Landroid/content/Context;Landroid/view/Window;La/b/k/f;Ljava/lang/Object;)V

    return-object v0
.end method

.method public static e(Landroid/app/Dialog;La/b/k/f;)La/b/k/g;
    .locals 3

    new-instance v0, La/b/k/h;

    .line 1
    invoke-virtual {p0}, Landroid/app/Dialog;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    move-result-object v2

    invoke-direct {v0, v1, v2, p1, p0}, La/b/k/h;-><init>(Landroid/content/Context;Landroid/view/Window;La/b/k/f;Ljava/lang/Object;)V

    return-object v0
.end method

.method public static j(La/b/k/g;)V
    .locals 4

    sget-object v0, La/b/k/g;->c:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    sget-object v1, La/b/k/g;->b:La/d/c;

    invoke-virtual {v1}, La/d/c;->iterator()Ljava/util/Iterator;

    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_0
    :goto_0
    move-object v2, v1

    check-cast v2, La/d/g$a;

    :try_start_1
    invoke-virtual {v2}, La/d/g$a;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/ref/WeakReference;

    invoke-virtual {v3}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/b/k/g;

    if-eq v3, p0, :cond_1

    if-nez v3, :cond_0

    :cond_1
    invoke-interface {v2}, Ljava/util/Iterator;->remove()V

    goto :goto_0

    :cond_2
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p0
.end method


# virtual methods
.method public abstract c(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
.end method

.method public abstract f()V
.end method

.method public abstract g()V
.end method

.method public abstract h(Landroid/os/Bundle;)V
.end method

.method public abstract i()V
.end method

.method public abstract k(I)Z
.end method

.method public abstract l(I)V
.end method

.method public abstract m(Landroid/view/View;)V
.end method

.method public abstract n(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
.end method

.method public abstract o(Ljava/lang/CharSequence;)V
.end method
