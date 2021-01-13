.class public La/b/k/h$d$a;
.super La/f/j/r;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = La/b/k/h$d;->b(La/b/o/a;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:La/b/k/h$d;


# direct methods
.method public constructor <init>(La/b/k/h$d;)V
    .locals 0

    iput-object p1, p0, La/b/k/h$d$a;->a:La/b/k/h$d;

    invoke-direct {p0}, La/f/j/r;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Landroid/view/View;)V
    .locals 1

    iget-object p1, p0, La/b/k/h$d$a;->a:La/b/k/h$d;

    iget-object p1, p1, La/b/k/h$d;->b:La/b/k/h;

    iget-object p1, p1, La/b/k/h;->p:Landroidx/appcompat/widget/ActionBarContextView;

    const/16 v0, 0x8

    invoke-virtual {p1, v0}, Landroidx/appcompat/widget/ActionBarContextView;->setVisibility(I)V

    iget-object p1, p0, La/b/k/h$d$a;->a:La/b/k/h$d;

    iget-object p1, p1, La/b/k/h$d;->b:La/b/k/h;

    iget-object v0, p1, La/b/k/h;->q:Landroid/widget/PopupWindow;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroid/widget/PopupWindow;->dismiss()V

    goto :goto_0

    :cond_0
    iget-object p1, p1, La/b/k/h;->p:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {p1}, Landroid/view/ViewGroup;->getParent()Landroid/view/ViewParent;

    move-result-object p1

    instance-of p1, p1, Landroid/view/View;

    if-eqz p1, :cond_1

    iget-object p1, p0, La/b/k/h$d$a;->a:La/b/k/h$d;

    iget-object p1, p1, La/b/k/h$d;->b:La/b/k/h;

    iget-object p1, p1, La/b/k/h;->p:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {p1}, Landroid/view/ViewGroup;->getParent()Landroid/view/ViewParent;

    move-result-object p1

    check-cast p1, Landroid/view/View;

    invoke-static {p1}, La/f/j/k;->s(Landroid/view/View;)V

    :cond_1
    :goto_0
    iget-object p1, p0, La/b/k/h$d$a;->a:La/b/k/h$d;

    iget-object p1, p1, La/b/k/h$d;->b:La/b/k/h;

    iget-object p1, p1, La/b/k/h;->p:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {p1}, Landroid/view/ViewGroup;->removeAllViews()V

    iget-object p1, p0, La/b/k/h$d$a;->a:La/b/k/h$d;

    iget-object p1, p1, La/b/k/h$d;->b:La/b/k/h;

    iget-object p1, p1, La/b/k/h;->s:La/f/j/p;

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, La/f/j/p;->d(La/f/j/q;)La/f/j/p;

    iget-object p1, p0, La/b/k/h$d$a;->a:La/b/k/h$d;

    iget-object p1, p1, La/b/k/h$d;->b:La/b/k/h;

    iput-object v0, p1, La/b/k/h;->s:La/f/j/p;

    iget-object p1, p1, La/b/k/h;->v:Landroid/view/ViewGroup;

    invoke-static {p1}, La/f/j/k;->s(Landroid/view/View;)V

    return-void
.end method
