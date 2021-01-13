.class public La/f/j/t$g;
.super La/f/j/t$f;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/f/j/t;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "g"
.end annotation


# direct methods
.method public constructor <init>(La/f/j/t;Landroid/view/WindowInsets;)V
    .locals 0

    invoke-direct {p0, p1, p2}, La/f/j/t$f;-><init>(La/f/j/t;Landroid/view/WindowInsets;)V

    return-void
.end method


# virtual methods
.method public g(IIII)La/f/j/t;
    .locals 1

    iget-object v0, p0, La/f/j/t$d;->b:Landroid/view/WindowInsets;

    invoke-virtual {v0, p1, p2, p3, p4}, Landroid/view/WindowInsets;->inset(IIII)Landroid/view/WindowInsets;

    move-result-object p1

    invoke-static {p1}, La/f/j/t;->h(Landroid/view/WindowInsets;)La/f/j/t;

    move-result-object p1

    return-object p1
.end method
