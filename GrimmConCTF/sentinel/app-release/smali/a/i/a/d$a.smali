.class public La/i/a/d$a;
.super La/i/a/h;
.source ""

# interfaces
.implements La/j/t;
.implements La/a/c;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/i/a/d;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "a"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "La/i/a/h<",
        "La/i/a/d;",
        ">;",
        "La/j/t;",
        "La/a/c;"
    }
.end annotation


# instance fields
.field public final synthetic g:La/i/a/d;


# direct methods
.method public constructor <init>(La/i/a/d;)V
    .locals 0

    iput-object p1, p0, La/i/a/d$a;->g:La/i/a/d;

    invoke-direct {p0, p1}, La/i/a/h;-><init>(La/i/a/d;)V

    return-void
.end method


# virtual methods
.method public a()La/j/d;
    .locals 1

    iget-object v0, p0, La/i/a/d$a;->g:La/i/a/d;

    iget-object v0, v0, La/i/a/d;->h:La/j/h;

    return-object v0
.end method

.method public b(I)Landroid/view/View;
    .locals 1

    iget-object v0, p0, La/i/a/d$a;->g:La/i/a/d;

    invoke-virtual {v0, p1}, Landroid/app/Activity;->findViewById(I)Landroid/view/View;

    move-result-object p1

    return-object p1
.end method

.method public c()Landroidx/activity/OnBackPressedDispatcher;
    .locals 1

    iget-object v0, p0, La/i/a/d$a;->g:La/i/a/d;

    .line 1
    iget-object v0, v0, Landroidx/activity/ComponentActivity;->f:Landroidx/activity/OnBackPressedDispatcher;

    return-object v0
.end method

.method public e()La/j/s;
    .locals 1

    iget-object v0, p0, La/i/a/d$a;->g:La/i/a/d;

    invoke-virtual {v0}, Landroidx/activity/ComponentActivity;->e()La/j/s;

    move-result-object v0

    return-object v0
.end method

.method public f()Z
    .locals 1

    iget-object v0, p0, La/i/a/d$a;->g:La/i/a/d;

    invoke-virtual {v0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroid/view/Window;->peekDecorView()Landroid/view/View;

    move-result-object v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method
