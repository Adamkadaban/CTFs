.class public La/b/k/l$a;
.super La/f/j/r;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = La/b/k/l;->run()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:La/b/k/l;


# direct methods
.method public constructor <init>(La/b/k/l;)V
    .locals 0

    iput-object p1, p0, La/b/k/l$a;->a:La/b/k/l;

    invoke-direct {p0}, La/f/j/r;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Landroid/view/View;)V
    .locals 1

    iget-object p1, p0, La/b/k/l$a;->a:La/b/k/l;

    iget-object p1, p1, La/b/k/l;->b:La/b/k/h;

    iget-object p1, p1, La/b/k/h;->p:Landroidx/appcompat/widget/ActionBarContextView;

    const/high16 v0, 0x3f800000    # 1.0f

    invoke-virtual {p1, v0}, Landroid/view/ViewGroup;->setAlpha(F)V

    iget-object p1, p0, La/b/k/l$a;->a:La/b/k/l;

    iget-object p1, p1, La/b/k/l;->b:La/b/k/h;

    iget-object p1, p1, La/b/k/h;->s:La/f/j/p;

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, La/f/j/p;->d(La/f/j/q;)La/f/j/p;

    iget-object p1, p0, La/b/k/l$a;->a:La/b/k/l;

    iget-object p1, p1, La/b/k/l;->b:La/b/k/h;

    iput-object v0, p1, La/b/k/h;->s:La/f/j/p;

    return-void
.end method

.method public b(Landroid/view/View;)V
    .locals 1

    iget-object p1, p0, La/b/k/l$a;->a:La/b/k/l;

    iget-object p1, p1, La/b/k/l;->b:La/b/k/h;

    iget-object p1, p1, La/b/k/h;->p:Landroidx/appcompat/widget/ActionBarContextView;

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Landroidx/appcompat/widget/ActionBarContextView;->setVisibility(I)V

    return-void
.end method
