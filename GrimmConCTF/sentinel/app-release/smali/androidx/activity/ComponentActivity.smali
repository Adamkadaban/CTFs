.class public Landroidx/activity/ComponentActivity;
.super La/f/c/d;
.source ""

# interfaces
.implements La/j/g;
.implements La/j/t;
.implements La/l/c;
.implements La/a/c;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/activity/ComponentActivity$b;
    }
.end annotation


# instance fields
.field public final c:La/j/h;

.field public final d:La/l/b;

.field public e:La/j/s;

.field public final f:Landroidx/activity/OnBackPressedDispatcher;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, La/f/c/d;-><init>()V

    new-instance v0, La/j/h;

    invoke-direct {v0, p0}, La/j/h;-><init>(La/j/g;)V

    iput-object v0, p0, Landroidx/activity/ComponentActivity;->c:La/j/h;

    .line 1
    new-instance v0, La/l/b;

    invoke-direct {v0, p0}, La/l/b;-><init>(La/l/c;)V

    .line 2
    iput-object v0, p0, Landroidx/activity/ComponentActivity;->d:La/l/b;

    new-instance v0, Landroidx/activity/OnBackPressedDispatcher;

    new-instance v1, Landroidx/activity/ComponentActivity$a;

    invoke-direct {v1, p0}, Landroidx/activity/ComponentActivity$a;-><init>(Landroidx/activity/ComponentActivity;)V

    invoke-direct {v0, v1}, Landroidx/activity/OnBackPressedDispatcher;-><init>(Ljava/lang/Runnable;)V

    iput-object v0, p0, Landroidx/activity/ComponentActivity;->f:Landroidx/activity/OnBackPressedDispatcher;

    .line 3
    iget-object v0, p0, Landroidx/activity/ComponentActivity;->c:La/j/h;

    if-eqz v0, :cond_0

    .line 4
    new-instance v1, Landroidx/activity/ComponentActivity$2;

    invoke-direct {v1, p0}, Landroidx/activity/ComponentActivity$2;-><init>(Landroidx/activity/ComponentActivity;)V

    invoke-virtual {v0, v1}, La/j/d;->a(La/j/f;)V

    .line 5
    iget-object v0, p0, Landroidx/activity/ComponentActivity;->c:La/j/h;

    .line 6
    new-instance v1, Landroidx/activity/ComponentActivity$3;

    invoke-direct {v1, p0}, Landroidx/activity/ComponentActivity$3;-><init>(Landroidx/activity/ComponentActivity;)V

    invoke-virtual {v0, v1}, La/j/d;->a(La/j/f;)V

    return-void

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "getLifecycle() returned null in ComponentActivity\'s constructor. Please make sure you are lazily constructing your Lifecycle in the first call to getLifecycle() rather than relying on field initialization."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static synthetic j(Landroidx/activity/ComponentActivity;)V
    .locals 0

    invoke-super {p0}, Landroid/app/Activity;->onBackPressed()V

    return-void
.end method


# virtual methods
.method public a()La/j/d;
    .locals 1

    iget-object v0, p0, Landroidx/activity/ComponentActivity;->c:La/j/h;

    return-object v0
.end method

.method public final c()Landroidx/activity/OnBackPressedDispatcher;
    .locals 1

    iget-object v0, p0, Landroidx/activity/ComponentActivity;->f:Landroidx/activity/OnBackPressedDispatcher;

    return-object v0
.end method

.method public final d()La/l/a;
    .locals 1

    iget-object v0, p0, Landroidx/activity/ComponentActivity;->d:La/l/b;

    .line 1
    iget-object v0, v0, La/l/b;->b:La/l/a;

    return-object v0
.end method

.method public e()La/j/s;
    .locals 2

    invoke-virtual {p0}, Landroid/app/Activity;->getApplication()Landroid/app/Application;

    move-result-object v0

    if-eqz v0, :cond_2

    iget-object v0, p0, Landroidx/activity/ComponentActivity;->e:La/j/s;

    if-nez v0, :cond_1

    invoke-virtual {p0}, Landroid/app/Activity;->getLastNonConfigurationInstance()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/activity/ComponentActivity$b;

    if-eqz v0, :cond_0

    iget-object v0, v0, Landroidx/activity/ComponentActivity$b;->a:La/j/s;

    iput-object v0, p0, Landroidx/activity/ComponentActivity;->e:La/j/s;

    :cond_0
    iget-object v0, p0, Landroidx/activity/ComponentActivity;->e:La/j/s;

    if-nez v0, :cond_1

    new-instance v0, La/j/s;

    invoke-direct {v0}, La/j/s;-><init>()V

    iput-object v0, p0, Landroidx/activity/ComponentActivity;->e:La/j/s;

    :cond_1
    iget-object v0, p0, Landroidx/activity/ComponentActivity;->e:La/j/s;

    return-object v0

    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Your activity is not yet attached to the Application instance. You can\'t request ViewModel before onCreate call."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public onBackPressed()V
    .locals 1

    iget-object v0, p0, Landroidx/activity/ComponentActivity;->f:Landroidx/activity/OnBackPressedDispatcher;

    invoke-virtual {v0}, Landroidx/activity/OnBackPressedDispatcher;->a()V

    return-void
.end method

.method public onCreate(Landroid/os/Bundle;)V
    .locals 1

    invoke-super {p0, p1}, La/f/c/d;->onCreate(Landroid/os/Bundle;)V

    iget-object v0, p0, Landroidx/activity/ComponentActivity;->d:La/l/b;

    invoke-virtual {v0, p1}, La/l/b;->a(Landroid/os/Bundle;)V

    invoke-static {p0}, La/j/o;->b(Landroid/app/Activity;)V

    return-void
.end method

.method public final onRetainNonConfigurationInstance()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Landroidx/activity/ComponentActivity;->e:La/j/s;

    if-nez v0, :cond_0

    invoke-virtual {p0}, Landroid/app/Activity;->getLastNonConfigurationInstance()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/activity/ComponentActivity$b;

    if-eqz v1, :cond_0

    iget-object v0, v1, Landroidx/activity/ComponentActivity$b;->a:La/j/s;

    :cond_0
    if-nez v0, :cond_1

    const/4 v0, 0x0

    return-object v0

    :cond_1
    new-instance v1, Landroidx/activity/ComponentActivity$b;

    invoke-direct {v1}, Landroidx/activity/ComponentActivity$b;-><init>()V

    iput-object v0, v1, Landroidx/activity/ComponentActivity$b;->a:La/j/s;

    return-object v1
.end method

.method public onSaveInstanceState(Landroid/os/Bundle;)V
    .locals 2

    .line 1
    iget-object v0, p0, Landroidx/activity/ComponentActivity;->c:La/j/h;

    .line 2
    instance-of v1, v0, La/j/h;

    if-eqz v1, :cond_0

    sget-object v1, La/j/d$b;->d:La/j/d$b;

    .line 3
    invoke-virtual {v0, v1}, La/j/h;->f(La/j/d$b;)V

    .line 4
    :cond_0
    invoke-super {p0, p1}, La/f/c/d;->onSaveInstanceState(Landroid/os/Bundle;)V

    iget-object v0, p0, Landroidx/activity/ComponentActivity;->d:La/l/b;

    invoke-virtual {v0, p1}, La/l/b;->b(Landroid/os/Bundle;)V

    return-void
.end method
