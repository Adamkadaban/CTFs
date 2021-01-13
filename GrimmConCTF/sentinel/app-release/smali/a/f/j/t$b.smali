.class public La/f/j/t$b;
.super La/f/j/t$c;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/f/j/t;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "b"
.end annotation


# instance fields
.field public final b:Landroid/view/WindowInsets$Builder;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, La/f/j/t$c;-><init>()V

    new-instance v0, Landroid/view/WindowInsets$Builder;

    invoke-direct {v0}, Landroid/view/WindowInsets$Builder;-><init>()V

    iput-object v0, p0, La/f/j/t$b;->b:Landroid/view/WindowInsets$Builder;

    return-void
.end method

.method public constructor <init>(La/f/j/t;)V
    .locals 1

    invoke-direct {p0}, La/f/j/t$c;-><init>()V

    invoke-virtual {p1}, La/f/j/t;->g()Landroid/view/WindowInsets;

    move-result-object p1

    new-instance v0, Landroid/view/WindowInsets$Builder;

    if-eqz p1, :cond_0

    invoke-direct {v0, p1}, Landroid/view/WindowInsets$Builder;-><init>(Landroid/view/WindowInsets;)V

    goto :goto_0

    :cond_0
    invoke-direct {v0}, Landroid/view/WindowInsets$Builder;-><init>()V

    :goto_0
    iput-object v0, p0, La/f/j/t$b;->b:Landroid/view/WindowInsets$Builder;

    return-void
.end method


# virtual methods
.method public a()La/f/j/t;
    .locals 1

    iget-object v0, p0, La/f/j/t$b;->b:Landroid/view/WindowInsets$Builder;

    invoke-virtual {v0}, Landroid/view/WindowInsets$Builder;->build()Landroid/view/WindowInsets;

    move-result-object v0

    invoke-static {v0}, La/f/j/t;->h(Landroid/view/WindowInsets;)La/f/j/t;

    move-result-object v0

    return-object v0
.end method

.method public b(La/f/e/b;)V
    .locals 4

    iget-object v0, p0, La/f/j/t$b;->b:Landroid/view/WindowInsets$Builder;

    .line 1
    iget v1, p1, La/f/e/b;->a:I

    iget v2, p1, La/f/e/b;->b:I

    iget v3, p1, La/f/e/b;->c:I

    iget p1, p1, La/f/e/b;->d:I

    invoke-static {v1, v2, v3, p1}, Landroid/graphics/Insets;->of(IIII)Landroid/graphics/Insets;

    move-result-object p1

    .line 2
    invoke-virtual {v0, p1}, Landroid/view/WindowInsets$Builder;->setStableInsets(Landroid/graphics/Insets;)Landroid/view/WindowInsets$Builder;

    return-void
.end method

.method public c(La/f/e/b;)V
    .locals 4

    iget-object v0, p0, La/f/j/t$b;->b:Landroid/view/WindowInsets$Builder;

    .line 1
    iget v1, p1, La/f/e/b;->a:I

    iget v2, p1, La/f/e/b;->b:I

    iget v3, p1, La/f/e/b;->c:I

    iget p1, p1, La/f/e/b;->d:I

    invoke-static {v1, v2, v3, p1}, Landroid/graphics/Insets;->of(IIII)Landroid/graphics/Insets;

    move-result-object p1

    .line 2
    invoke-virtual {v0, p1}, Landroid/view/WindowInsets$Builder;->setSystemWindowInsets(Landroid/graphics/Insets;)Landroid/view/WindowInsets$Builder;

    return-void
.end method
