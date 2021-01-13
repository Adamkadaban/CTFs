.class public La/f/j/k$a;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements Landroid/view/View$OnApplyWindowInsetsListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = La/f/j/k;->x(Landroid/view/View;La/f/j/i;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:La/f/j/i;


# direct methods
.method public constructor <init>(La/f/j/i;)V
    .locals 0

    iput-object p1, p0, La/f/j/k$a;->a:La/f/j/i;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onApplyWindowInsets(Landroid/view/View;Landroid/view/WindowInsets;)Landroid/view/WindowInsets;
    .locals 6

    .line 1
    new-instance v0, La/f/j/t;

    const/4 v1, 0x0

    if-eqz p2, :cond_3

    invoke-direct {v0, p2}, La/f/j/t;-><init>(Landroid/view/WindowInsets;)V

    .line 2
    iget-object p2, p0, La/f/j/k$a;->a:La/f/j/i;

    check-cast p2, La/b/k/i;

    if-eqz p2, :cond_2

    .line 3
    invoke-virtual {v0}, La/f/j/t;->d()I

    move-result v2

    iget-object p2, p2, La/b/k/i;->a:La/b/k/h;

    invoke-virtual {p2, v0, v1}, La/b/k/h;->N(La/f/j/t;Landroid/graphics/Rect;)I

    move-result p2

    if-eq v2, p2, :cond_1

    invoke-virtual {v0}, La/f/j/t;->b()I

    move-result v1

    invoke-virtual {v0}, La/f/j/t;->c()I

    move-result v2

    invoke-virtual {v0}, La/f/j/t;->a()I

    move-result v3

    .line 4
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v5, 0x1d

    if-lt v4, v5, :cond_0

    new-instance v4, La/f/j/t$b;

    invoke-direct {v4, v0}, La/f/j/t$b;-><init>(La/f/j/t;)V

    goto :goto_0

    :cond_0
    new-instance v4, La/f/j/t$a;

    invoke-direct {v4, v0}, La/f/j/t$a;-><init>(La/f/j/t;)V

    .line 5
    :goto_0
    invoke-static {v1, p2, v2, v3}, La/f/e/b;->a(IIII)La/f/e/b;

    move-result-object p2

    .line 6
    invoke-virtual {v4, p2}, La/f/j/t$c;->c(La/f/e/b;)V

    .line 7
    invoke-virtual {v4}, La/f/j/t$c;->a()La/f/j/t;

    move-result-object v0

    .line 8
    :cond_1
    invoke-static {p1, v0}, La/f/j/k;->o(Landroid/view/View;La/f/j/t;)La/f/j/t;

    move-result-object p1

    .line 9
    invoke-virtual {p1}, La/f/j/t;->g()Landroid/view/WindowInsets;

    move-result-object p1

    return-object p1

    .line 10
    :cond_2
    throw v1

    .line 11
    :cond_3
    throw v1
.end method
