.class public La/b/p/t;
.super Landroid/widget/SeekBar;
.source ""


# instance fields
.field public final b:La/b/p/u;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 1

    sget v0, La/b/a;->seekBarStyle:I

    .line 1
    invoke-direct {p0, p1, p2, v0}, Landroid/widget/SeekBar;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    invoke-virtual {p0}, Landroid/widget/SeekBar;->getContext()Landroid/content/Context;

    move-result-object p1

    invoke-static {p0, p1}, La/b/p/s0;->a(Landroid/view/View;Landroid/content/Context;)V

    new-instance p1, La/b/p/u;

    invoke-direct {p1, p0}, La/b/p/u;-><init>(Landroid/widget/SeekBar;)V

    iput-object p1, p0, La/b/p/t;->b:La/b/p/u;

    invoke-virtual {p1, p2, v0}, La/b/p/u;->a(Landroid/util/AttributeSet;I)V

    return-void
.end method


# virtual methods
.method public drawableStateChanged()V
    .locals 3

    invoke-super {p0}, Landroid/widget/SeekBar;->drawableStateChanged()V

    iget-object v0, p0, La/b/p/t;->b:La/b/p/u;

    .line 1
    iget-object v1, v0, La/b/p/u;->e:Landroid/graphics/drawable/Drawable;

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Landroid/graphics/drawable/Drawable;->isStateful()Z

    move-result v2

    if-eqz v2, :cond_0

    iget-object v2, v0, La/b/p/u;->d:Landroid/widget/SeekBar;

    invoke-virtual {v2}, Landroid/widget/SeekBar;->getDrawableState()[I

    move-result-object v2

    invoke-virtual {v1, v2}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    move-result v2

    if-eqz v2, :cond_0

    iget-object v0, v0, La/b/p/u;->d:Landroid/widget/SeekBar;

    invoke-virtual {v0, v1}, Landroid/widget/SeekBar;->invalidateDrawable(Landroid/graphics/drawable/Drawable;)V

    :cond_0
    return-void
.end method

.method public jumpDrawablesToCurrentState()V
    .locals 1

    invoke-super {p0}, Landroid/widget/SeekBar;->jumpDrawablesToCurrentState()V

    iget-object v0, p0, La/b/p/t;->b:La/b/p/u;

    .line 1
    iget-object v0, v0, La/b/p/u;->e:Landroid/graphics/drawable/Drawable;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->jumpToCurrentState()V

    :cond_0
    return-void
.end method

.method public declared-synchronized onDraw(Landroid/graphics/Canvas;)V
    .locals 1

    monitor-enter p0

    :try_start_0
    invoke-super {p0, p1}, Landroid/widget/SeekBar;->onDraw(Landroid/graphics/Canvas;)V

    iget-object v0, p0, La/b/p/t;->b:La/b/p/u;

    invoke-virtual {v0, p1}, La/b/p/u;->d(Landroid/graphics/Canvas;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    return-void

    :catchall_0
    move-exception p1

    monitor-exit p0

    throw p1
.end method
