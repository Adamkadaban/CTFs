.class public final La/f/c/b$c;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements Landroid/app/Application$ActivityLifecycleCallbacks;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/f/c/b;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "c"
.end annotation


# instance fields
.field public a:Ljava/lang/Object;

.field public b:Landroid/app/Activity;

.field public c:Z

.field public d:Z

.field public e:Z


# direct methods
.method public constructor <init>(Landroid/app/Activity;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-boolean v0, p0, La/f/c/b$c;->c:Z

    iput-boolean v0, p0, La/f/c/b$c;->d:Z

    iput-boolean v0, p0, La/f/c/b$c;->e:Z

    iput-object p1, p0, La/f/c/b$c;->b:Landroid/app/Activity;

    return-void
.end method


# virtual methods
.method public onActivityCreated(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 0

    return-void
.end method

.method public onActivityDestroyed(Landroid/app/Activity;)V
    .locals 1

    iget-object v0, p0, La/f/c/b$c;->b:Landroid/app/Activity;

    if-ne v0, p1, :cond_0

    const/4 p1, 0x0

    iput-object p1, p0, La/f/c/b$c;->b:Landroid/app/Activity;

    const/4 p1, 0x1

    iput-boolean p1, p0, La/f/c/b$c;->d:Z

    :cond_0
    return-void
.end method

.method public onActivityPaused(Landroid/app/Activity;)V
    .locals 5

    iget-boolean v0, p0, La/f/c/b$c;->d:Z

    if-eqz v0, :cond_1

    iget-boolean v0, p0, La/f/c/b$c;->e:Z

    if-nez v0, :cond_1

    iget-boolean v0, p0, La/f/c/b$c;->c:Z

    if-nez v0, :cond_1

    iget-object v0, p0, La/f/c/b$c;->a:Ljava/lang/Object;

    const/4 v1, 0x0

    const/4 v2, 0x1

    .line 1
    :try_start_0
    sget-object v3, La/f/c/b;->c:Ljava/lang/reflect/Field;

    invoke-virtual {v3, p1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    if-eq v3, v0, :cond_0

    goto :goto_0

    :cond_0
    sget-object v0, La/f/c/b;->b:Ljava/lang/reflect/Field;

    invoke-virtual {v0, p1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, La/f/c/b;->g:Landroid/os/Handler;

    new-instance v4, La/f/c/c;

    invoke-direct {v4, p1, v3}, La/f/c/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v0, v4}, Landroid/os/Handler;->postAtFrontOfQueue(Ljava/lang/Runnable;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    move v1, v2

    goto :goto_0

    :catchall_0
    move-exception p1

    const-string v0, "ActivityRecreator"

    const-string v3, "Exception while fetching field values"

    invoke-static {v0, v3, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :goto_0
    if-eqz v1, :cond_1

    .line 2
    iput-boolean v2, p0, La/f/c/b$c;->e:Z

    const/4 p1, 0x0

    iput-object p1, p0, La/f/c/b$c;->a:Ljava/lang/Object;

    :cond_1
    return-void
.end method

.method public onActivityResumed(Landroid/app/Activity;)V
    .locals 0

    return-void
.end method

.method public onActivitySaveInstanceState(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 0

    return-void
.end method

.method public onActivityStarted(Landroid/app/Activity;)V
    .locals 1

    iget-object v0, p0, La/f/c/b$c;->b:Landroid/app/Activity;

    if-ne v0, p1, :cond_0

    const/4 p1, 0x1

    iput-boolean p1, p0, La/f/c/b$c;->c:Z

    :cond_0
    return-void
.end method

.method public onActivityStopped(Landroid/app/Activity;)V
    .locals 0

    return-void
.end method
