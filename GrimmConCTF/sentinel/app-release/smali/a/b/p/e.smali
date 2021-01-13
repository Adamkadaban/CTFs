.class public La/b/p/e;
.super Ljava/lang/Object;
.source ""


# instance fields
.field public final a:Landroid/view/View;

.field public final b:La/b/p/j;

.field public c:I

.field public d:La/b/p/v0;

.field public e:La/b/p/v0;

.field public f:La/b/p/v0;


# direct methods
.method public constructor <init>(Landroid/view/View;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, -0x1

    iput v0, p0, La/b/p/e;->c:I

    iput-object p1, p0, La/b/p/e;->a:Landroid/view/View;

    invoke-static {}, La/b/p/j;->a()La/b/p/j;

    move-result-object p1

    iput-object p1, p0, La/b/p/e;->b:La/b/p/j;

    return-void
.end method


# virtual methods
.method public a()V
    .locals 5

    iget-object v0, p0, La/b/p/e;->a:Landroid/view/View;

    invoke-virtual {v0}, Landroid/view/View;->getBackground()Landroid/graphics/drawable/Drawable;

    move-result-object v0

    if-eqz v0, :cond_8

    .line 1
    iget-object v1, p0, La/b/p/e;->d:La/b/p/v0;

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-eqz v1, :cond_0

    move v1, v2

    goto :goto_0

    :cond_0
    move v1, v3

    :goto_0
    if-eqz v1, :cond_6

    .line 2
    iget-object v1, p0, La/b/p/e;->f:La/b/p/v0;

    if-nez v1, :cond_1

    new-instance v1, La/b/p/v0;

    invoke-direct {v1}, La/b/p/v0;-><init>()V

    iput-object v1, p0, La/b/p/e;->f:La/b/p/v0;

    :cond_1
    iget-object v1, p0, La/b/p/e;->f:La/b/p/v0;

    const/4 v4, 0x0

    .line 3
    iput-object v4, v1, La/b/p/v0;->a:Landroid/content/res/ColorStateList;

    iput-boolean v3, v1, La/b/p/v0;->d:Z

    iput-object v4, v1, La/b/p/v0;->b:Landroid/graphics/PorterDuff$Mode;

    iput-boolean v3, v1, La/b/p/v0;->c:Z

    .line 4
    iget-object v4, p0, La/b/p/e;->a:Landroid/view/View;

    invoke-static {v4}, La/f/j/k;->e(Landroid/view/View;)Landroid/content/res/ColorStateList;

    move-result-object v4

    if-eqz v4, :cond_2

    iput-boolean v2, v1, La/b/p/v0;->d:Z

    iput-object v4, v1, La/b/p/v0;->a:Landroid/content/res/ColorStateList;

    :cond_2
    iget-object v4, p0, La/b/p/e;->a:Landroid/view/View;

    .line 5
    invoke-virtual {v4}, Landroid/view/View;->getBackgroundTintMode()Landroid/graphics/PorterDuff$Mode;

    move-result-object v4

    if-eqz v4, :cond_3

    .line 6
    iput-boolean v2, v1, La/b/p/v0;->c:Z

    iput-object v4, v1, La/b/p/v0;->b:Landroid/graphics/PorterDuff$Mode;

    :cond_3
    iget-boolean v4, v1, La/b/p/v0;->d:Z

    if-nez v4, :cond_5

    iget-boolean v4, v1, La/b/p/v0;->c:Z

    if-eqz v4, :cond_4

    goto :goto_1

    :cond_4
    move v2, v3

    goto :goto_2

    :cond_5
    :goto_1
    iget-object v3, p0, La/b/p/e;->a:Landroid/view/View;

    invoke-virtual {v3}, Landroid/view/View;->getDrawableState()[I

    move-result-object v3

    invoke-static {v0, v1, v3}, La/b/p/j;->e(Landroid/graphics/drawable/Drawable;La/b/p/v0;[I)V

    :goto_2
    if-eqz v2, :cond_6

    return-void

    .line 7
    :cond_6
    iget-object v1, p0, La/b/p/e;->e:La/b/p/v0;

    if-eqz v1, :cond_7

    iget-object v2, p0, La/b/p/e;->a:Landroid/view/View;

    invoke-virtual {v2}, Landroid/view/View;->getDrawableState()[I

    move-result-object v2

    invoke-static {v0, v1, v2}, La/b/p/j;->e(Landroid/graphics/drawable/Drawable;La/b/p/v0;[I)V

    goto :goto_3

    :cond_7
    iget-object v1, p0, La/b/p/e;->d:La/b/p/v0;

    if-eqz v1, :cond_8

    iget-object v2, p0, La/b/p/e;->a:Landroid/view/View;

    invoke-virtual {v2}, Landroid/view/View;->getDrawableState()[I

    move-result-object v2

    invoke-static {v0, v1, v2}, La/b/p/j;->e(Landroid/graphics/drawable/Drawable;La/b/p/v0;[I)V

    :cond_8
    :goto_3
    return-void
.end method

.method public b()Landroid/content/res/ColorStateList;
    .locals 1

    iget-object v0, p0, La/b/p/e;->e:La/b/p/v0;

    if-eqz v0, :cond_0

    iget-object v0, v0, La/b/p/v0;->a:Landroid/content/res/ColorStateList;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return-object v0
.end method

.method public c()Landroid/graphics/PorterDuff$Mode;
    .locals 1

    iget-object v0, p0, La/b/p/e;->e:La/b/p/v0;

    if-eqz v0, :cond_0

    iget-object v0, v0, La/b/p/v0;->b:Landroid/graphics/PorterDuff$Mode;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return-object v0
.end method

.method public d(Landroid/util/AttributeSet;I)V
    .locals 8

    iget-object v0, p0, La/b/p/e;->a:Landroid/view/View;

    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v0

    sget-object v1, La/b/j;->ViewBackgroundHelper:[I

    const/4 v2, 0x0

    invoke-static {v0, p1, v1, p2, v2}, La/b/p/x0;->o(Landroid/content/Context;Landroid/util/AttributeSet;[III)La/b/p/x0;

    move-result-object v0

    iget-object v1, p0, La/b/p/e;->a:Landroid/view/View;

    invoke-virtual {v1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v2

    sget-object v3, La/b/j;->ViewBackgroundHelper:[I

    .line 1
    iget-object v5, v0, La/b/p/x0;->b:Landroid/content/res/TypedArray;

    const/4 v7, 0x0

    move-object v4, p1

    move v6, p2

    .line 2
    invoke-static/range {v1 .. v7}, La/f/j/k;->t(Landroid/view/View;Landroid/content/Context;[ILandroid/util/AttributeSet;Landroid/content/res/TypedArray;II)V

    :try_start_0
    sget p1, La/b/j;->ViewBackgroundHelper_android_background:I

    invoke-virtual {v0, p1}, La/b/p/x0;->m(I)Z

    move-result p1

    const/4 p2, -0x1

    if-eqz p1, :cond_0

    sget p1, La/b/j;->ViewBackgroundHelper_android_background:I

    invoke-virtual {v0, p1, p2}, La/b/p/x0;->j(II)I

    move-result p1

    iput p1, p0, La/b/p/e;->c:I

    iget-object p1, p0, La/b/p/e;->b:La/b/p/j;

    iget-object v1, p0, La/b/p/e;->a:Landroid/view/View;

    invoke-virtual {v1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    iget v2, p0, La/b/p/e;->c:I

    invoke-virtual {p1, v1, v2}, La/b/p/j;->c(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-virtual {p0, p1}, La/b/p/e;->g(Landroid/content/res/ColorStateList;)V

    :cond_0
    sget p1, La/b/j;->ViewBackgroundHelper_backgroundTint:I

    invoke-virtual {v0, p1}, La/b/p/x0;->m(I)Z

    move-result p1

    if-eqz p1, :cond_1

    iget-object p1, p0, La/b/p/e;->a:Landroid/view/View;

    sget v1, La/b/j;->ViewBackgroundHelper_backgroundTint:I

    invoke-virtual {v0, v1}, La/b/p/x0;->b(I)Landroid/content/res/ColorStateList;

    move-result-object v1

    .line 3
    invoke-virtual {p1, v1}, Landroid/view/View;->setBackgroundTintList(Landroid/content/res/ColorStateList;)V

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    .line 4
    :cond_1
    :goto_0
    sget p1, La/b/j;->ViewBackgroundHelper_backgroundTintMode:I

    invoke-virtual {v0, p1}, La/b/p/x0;->m(I)Z

    move-result p1

    if-eqz p1, :cond_2

    iget-object p1, p0, La/b/p/e;->a:Landroid/view/View;

    sget v1, La/b/j;->ViewBackgroundHelper_backgroundTintMode:I

    invoke-virtual {v0, v1, p2}, La/b/p/x0;->h(II)I

    move-result p2

    const/4 v1, 0x0

    invoke-static {p2, v1}, La/b/p/e0;->c(ILandroid/graphics/PorterDuff$Mode;)Landroid/graphics/PorterDuff$Mode;

    move-result-object p2

    .line 5
    invoke-virtual {p1, p2}, Landroid/view/View;->setBackgroundTintMode(Landroid/graphics/PorterDuff$Mode;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    :cond_2
    iget-object p1, v0, La/b/p/x0;->b:Landroid/content/res/TypedArray;

    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    return-void

    :goto_1
    iget-object p2, v0, La/b/p/x0;->b:Landroid/content/res/TypedArray;

    invoke-virtual {p2}, Landroid/content/res/TypedArray;->recycle()V

    .line 7
    throw p1
.end method

.method public e()V
    .locals 1

    const/4 v0, -0x1

    iput v0, p0, La/b/p/e;->c:I

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, La/b/p/e;->g(Landroid/content/res/ColorStateList;)V

    invoke-virtual {p0}, La/b/p/e;->a()V

    return-void
.end method

.method public f(I)V
    .locals 2

    iput p1, p0, La/b/p/e;->c:I

    iget-object v0, p0, La/b/p/e;->b:La/b/p/j;

    if-eqz v0, :cond_0

    iget-object v1, p0, La/b/p/e;->a:Landroid/view/View;

    invoke-virtual {v1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-virtual {v0, v1, p1}, La/b/p/j;->c(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    move-result-object p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    invoke-virtual {p0, p1}, La/b/p/e;->g(Landroid/content/res/ColorStateList;)V

    invoke-virtual {p0}, La/b/p/e;->a()V

    return-void
.end method

.method public g(Landroid/content/res/ColorStateList;)V
    .locals 1

    if-eqz p1, :cond_1

    iget-object v0, p0, La/b/p/e;->d:La/b/p/v0;

    if-nez v0, :cond_0

    new-instance v0, La/b/p/v0;

    invoke-direct {v0}, La/b/p/v0;-><init>()V

    iput-object v0, p0, La/b/p/e;->d:La/b/p/v0;

    :cond_0
    iget-object v0, p0, La/b/p/e;->d:La/b/p/v0;

    iput-object p1, v0, La/b/p/v0;->a:Landroid/content/res/ColorStateList;

    const/4 p1, 0x1

    iput-boolean p1, v0, La/b/p/v0;->d:Z

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    iput-object p1, p0, La/b/p/e;->d:La/b/p/v0;

    :goto_0
    invoke-virtual {p0}, La/b/p/e;->a()V

    return-void
.end method

.method public h(Landroid/content/res/ColorStateList;)V
    .locals 1

    iget-object v0, p0, La/b/p/e;->e:La/b/p/v0;

    if-nez v0, :cond_0

    new-instance v0, La/b/p/v0;

    invoke-direct {v0}, La/b/p/v0;-><init>()V

    iput-object v0, p0, La/b/p/e;->e:La/b/p/v0;

    :cond_0
    iget-object v0, p0, La/b/p/e;->e:La/b/p/v0;

    iput-object p1, v0, La/b/p/v0;->a:Landroid/content/res/ColorStateList;

    const/4 p1, 0x1

    iput-boolean p1, v0, La/b/p/v0;->d:Z

    invoke-virtual {p0}, La/b/p/e;->a()V

    return-void
.end method

.method public i(Landroid/graphics/PorterDuff$Mode;)V
    .locals 1

    iget-object v0, p0, La/b/p/e;->e:La/b/p/v0;

    if-nez v0, :cond_0

    new-instance v0, La/b/p/v0;

    invoke-direct {v0}, La/b/p/v0;-><init>()V

    iput-object v0, p0, La/b/p/e;->e:La/b/p/v0;

    :cond_0
    iget-object v0, p0, La/b/p/e;->e:La/b/p/v0;

    iput-object p1, v0, La/b/p/v0;->b:Landroid/graphics/PorterDuff$Mode;

    const/4 p1, 0x1

    iput-boolean p1, v0, La/b/p/v0;->c:Z

    invoke-virtual {p0}, La/b/p/e;->a()V

    return-void
.end method
