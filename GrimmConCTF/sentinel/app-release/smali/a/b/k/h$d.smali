.class public La/b/k/h$d;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements La/b/o/a$a;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/b/k/h;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "d"
.end annotation


# instance fields
.field public a:La/b/o/a$a;

.field public final synthetic b:La/b/k/h;


# direct methods
.method public constructor <init>(La/b/k/h;La/b/o/a$a;)V
    .locals 0

    iput-object p1, p0, La/b/k/h$d;->b:La/b/k/h;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, La/b/k/h$d;->a:La/b/o/a$a;

    return-void
.end method


# virtual methods
.method public a(La/b/o/a;Landroid/view/Menu;)Z
    .locals 1

    iget-object v0, p0, La/b/k/h$d;->b:La/b/k/h;

    iget-object v0, v0, La/b/k/h;->v:Landroid/view/ViewGroup;

    invoke-static {v0}, La/f/j/k;->s(Landroid/view/View;)V

    iget-object v0, p0, La/b/k/h$d;->a:La/b/o/a$a;

    invoke-interface {v0, p1, p2}, La/b/o/a$a;->a(La/b/o/a;Landroid/view/Menu;)Z

    move-result p1

    return p1
.end method

.method public b(La/b/o/a;)V
    .locals 2

    iget-object v0, p0, La/b/k/h$d;->a:La/b/o/a$a;

    invoke-interface {v0, p1}, La/b/o/a$a;->b(La/b/o/a;)V

    iget-object p1, p0, La/b/k/h$d;->b:La/b/k/h;

    iget-object v0, p1, La/b/k/h;->q:Landroid/widget/PopupWindow;

    if-eqz v0, :cond_0

    iget-object p1, p1, La/b/k/h;->f:Landroid/view/Window;

    invoke-virtual {p1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object p1

    iget-object v0, p0, La/b/k/h$d;->b:La/b/k/h;

    iget-object v0, v0, La/b/k/h;->r:Ljava/lang/Runnable;

    invoke-virtual {p1, v0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    :cond_0
    iget-object p1, p0, La/b/k/h$d;->b:La/b/k/h;

    iget-object v0, p1, La/b/k/h;->p:Landroidx/appcompat/widget/ActionBarContextView;

    if-eqz v0, :cond_1

    invoke-virtual {p1}, La/b/k/h;->y()V

    iget-object p1, p0, La/b/k/h$d;->b:La/b/k/h;

    iget-object v0, p1, La/b/k/h;->p:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-static {v0}, La/f/j/k;->a(Landroid/view/View;)La/f/j/p;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, La/f/j/p;->a(F)La/f/j/p;

    iput-object v0, p1, La/b/k/h;->s:La/f/j/p;

    iget-object p1, p0, La/b/k/h$d;->b:La/b/k/h;

    iget-object p1, p1, La/b/k/h;->s:La/f/j/p;

    new-instance v0, La/b/k/h$d$a;

    invoke-direct {v0, p0}, La/b/k/h$d$a;-><init>(La/b/k/h$d;)V

    .line 1
    iget-object v1, p1, La/f/j/p;->a:Ljava/lang/ref/WeakReference;

    invoke-virtual {v1}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/view/View;

    if-eqz v1, :cond_1

    invoke-virtual {p1, v1, v0}, La/f/j/p;->e(Landroid/view/View;La/f/j/q;)V

    .line 2
    :cond_1
    iget-object p1, p0, La/b/k/h$d;->b:La/b/k/h;

    iget-object v0, p1, La/b/k/h;->h:La/b/k/f;

    if-eqz v0, :cond_2

    iget-object p1, p1, La/b/k/h;->o:La/b/o/a;

    invoke-interface {v0, p1}, La/b/k/f;->f(La/b/o/a;)V

    :cond_2
    iget-object p1, p0, La/b/k/h$d;->b:La/b/k/h;

    const/4 v0, 0x0

    iput-object v0, p1, La/b/k/h;->o:La/b/o/a;

    iget-object p1, p1, La/b/k/h;->v:Landroid/view/ViewGroup;

    invoke-static {p1}, La/f/j/k;->s(Landroid/view/View;)V

    return-void
.end method

.method public c(La/b/o/a;Landroid/view/MenuItem;)Z
    .locals 1

    iget-object v0, p0, La/b/k/h$d;->a:La/b/o/a$a;

    invoke-interface {v0, p1, p2}, La/b/o/a$a;->c(La/b/o/a;Landroid/view/MenuItem;)Z

    move-result p1

    return p1
.end method

.method public d(La/b/o/a;Landroid/view/Menu;)Z
    .locals 1

    iget-object v0, p0, La/b/k/h$d;->a:La/b/o/a$a;

    invoke-interface {v0, p1, p2}, La/b/o/a$a;->d(La/b/o/a;Landroid/view/Menu;)Z

    move-result p1

    return p1
.end method
