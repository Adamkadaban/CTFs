.class public La/j/o;
.super Landroid/app/Fragment;
.source ""


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/j/o$a;
    }
.end annotation


# instance fields
.field public b:La/j/o$a;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/app/Fragment;-><init>()V

    return-void
.end method

.method public static b(Landroid/app/Activity;)V
    .locals 3

    invoke-virtual {p0}, Landroid/app/Activity;->getFragmentManager()Landroid/app/FragmentManager;

    move-result-object p0

    const-string v0, "androidx.lifecycle.LifecycleDispatcher.report_fragment_tag"

    invoke-virtual {p0, v0}, Landroid/app/FragmentManager;->findFragmentByTag(Ljava/lang/String;)Landroid/app/Fragment;

    move-result-object v1

    if-nez v1, :cond_0

    invoke-virtual {p0}, Landroid/app/FragmentManager;->beginTransaction()Landroid/app/FragmentTransaction;

    move-result-object v1

    new-instance v2, La/j/o;

    invoke-direct {v2}, La/j/o;-><init>()V

    invoke-virtual {v1, v2, v0}, Landroid/app/FragmentTransaction;->add(Landroid/app/Fragment;Ljava/lang/String;)Landroid/app/FragmentTransaction;

    move-result-object v0

    invoke-virtual {v0}, Landroid/app/FragmentTransaction;->commit()I

    invoke-virtual {p0}, Landroid/app/FragmentManager;->executePendingTransactions()Z

    :cond_0
    return-void
.end method


# virtual methods
.method public final a(La/j/d$a;)V
    .locals 2

    invoke-virtual {p0}, Landroid/app/Fragment;->getActivity()Landroid/app/Activity;

    move-result-object v0

    instance-of v1, v0, La/j/i;

    if-eqz v1, :cond_0

    check-cast v0, La/j/i;

    invoke-interface {v0}, La/j/i;->a()La/j/h;

    move-result-object v0

    invoke-virtual {v0, p1}, La/j/h;->d(La/j/d$a;)V

    return-void

    :cond_0
    instance-of v1, v0, La/j/g;

    if-eqz v1, :cond_1

    check-cast v0, La/j/g;

    invoke-interface {v0}, La/j/g;->a()La/j/d;

    move-result-object v0

    instance-of v1, v0, La/j/h;

    if-eqz v1, :cond_1

    check-cast v0, La/j/h;

    invoke-virtual {v0, p1}, La/j/h;->d(La/j/d$a;)V

    :cond_1
    return-void
.end method

.method public onActivityCreated(Landroid/os/Bundle;)V
    .locals 0

    invoke-super {p0, p1}, Landroid/app/Fragment;->onActivityCreated(Landroid/os/Bundle;)V

    iget-object p1, p0, La/j/o;->b:La/j/o$a;

    if-eqz p1, :cond_0

    .line 1
    invoke-interface {p1}, La/j/o$a;->a()V

    .line 2
    :cond_0
    sget-object p1, La/j/d$a;->ON_CREATE:La/j/d$a;

    invoke-virtual {p0, p1}, La/j/o;->a(La/j/d$a;)V

    return-void
.end method

.method public onDestroy()V
    .locals 1

    invoke-super {p0}, Landroid/app/Fragment;->onDestroy()V

    sget-object v0, La/j/d$a;->ON_DESTROY:La/j/d$a;

    invoke-virtual {p0, v0}, La/j/o;->a(La/j/d$a;)V

    const/4 v0, 0x0

    iput-object v0, p0, La/j/o;->b:La/j/o$a;

    return-void
.end method

.method public onPause()V
    .locals 1

    invoke-super {p0}, Landroid/app/Fragment;->onPause()V

    sget-object v0, La/j/d$a;->ON_PAUSE:La/j/d$a;

    invoke-virtual {p0, v0}, La/j/o;->a(La/j/d$a;)V

    return-void
.end method

.method public onResume()V
    .locals 1

    invoke-super {p0}, Landroid/app/Fragment;->onResume()V

    iget-object v0, p0, La/j/o;->b:La/j/o$a;

    if-eqz v0, :cond_0

    .line 1
    invoke-interface {v0}, La/j/o$a;->b()V

    .line 2
    :cond_0
    sget-object v0, La/j/d$a;->ON_RESUME:La/j/d$a;

    invoke-virtual {p0, v0}, La/j/o;->a(La/j/d$a;)V

    return-void
.end method

.method public onStart()V
    .locals 1

    invoke-super {p0}, Landroid/app/Fragment;->onStart()V

    iget-object v0, p0, La/j/o;->b:La/j/o$a;

    if-eqz v0, :cond_0

    .line 1
    invoke-interface {v0}, La/j/o$a;->c()V

    .line 2
    :cond_0
    sget-object v0, La/j/d$a;->ON_START:La/j/d$a;

    invoke-virtual {p0, v0}, La/j/o;->a(La/j/d$a;)V

    return-void
.end method

.method public onStop()V
    .locals 1

    invoke-super {p0}, Landroid/app/Fragment;->onStop()V

    sget-object v0, La/j/d$a;->ON_STOP:La/j/d$a;

    invoke-virtual {p0, v0}, La/j/o;->a(La/j/d$a;)V

    return-void
.end method
