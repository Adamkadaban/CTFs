.class public La/b/p/w$d$b;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = La/b/p/w$d;->f(II)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic b:La/b/p/w$d;


# direct methods
.method public constructor <init>(La/b/p/w$d;)V
    .locals 0

    iput-object p1, p0, La/b/p/w$d$b;->b:La/b/p/w$d;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onGlobalLayout()V
    .locals 3

    iget-object v0, p0, La/b/p/w$d$b;->b:La/b/p/w$d;

    iget-object v1, v0, La/b/p/w$d;->J:La/b/p/w;

    if-eqz v0, :cond_2

    .line 1
    invoke-static {v1}, La/f/j/k;->l(Landroid/view/View;)Z

    move-result v2

    if-eqz v2, :cond_0

    iget-object v0, v0, La/b/p/w$d;->H:Landroid/graphics/Rect;

    invoke-virtual {v1, v0}, Landroid/view/View;->getGlobalVisibleRect(Landroid/graphics/Rect;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-nez v0, :cond_1

    .line 2
    iget-object v0, p0, La/b/p/w$d$b;->b:La/b/p/w$d;

    invoke-virtual {v0}, La/b/p/k0;->dismiss()V

    goto :goto_1

    :cond_1
    iget-object v0, p0, La/b/p/w$d$b;->b:La/b/p/w$d;

    invoke-virtual {v0}, La/b/p/w$d;->u()V

    iget-object v0, p0, La/b/p/w$d$b;->b:La/b/p/w$d;

    invoke-static {v0}, La/b/p/w$d;->t(La/b/p/w$d;)V

    :goto_1
    return-void

    :cond_2
    const/4 v0, 0x0

    .line 3
    throw v0
.end method
