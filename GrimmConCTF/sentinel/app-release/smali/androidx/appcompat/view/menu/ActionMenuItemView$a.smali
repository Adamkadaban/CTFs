.class public Landroidx/appcompat/view/menu/ActionMenuItemView$a;
.super La/b/p/h0;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/ActionMenuItemView;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "a"
.end annotation


# instance fields
.field public final synthetic k:Landroidx/appcompat/view/menu/ActionMenuItemView;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/ActionMenuItemView;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/ActionMenuItemView$a;->k:Landroidx/appcompat/view/menu/ActionMenuItemView;

    invoke-direct {p0, p1}, La/b/p/h0;-><init>(Landroid/view/View;)V

    return-void
.end method


# virtual methods
.method public b()La/b/o/i/p;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/ActionMenuItemView$a;->k:Landroidx/appcompat/view/menu/ActionMenuItemView;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ActionMenuItemView;->k:Landroidx/appcompat/view/menu/ActionMenuItemView$b;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast v0, La/b/p/c$b;

    .line 1
    iget-object v0, v0, La/b/p/c$b;->a:La/b/p/c;

    iget-object v0, v0, La/b/p/c;->v:La/b/p/c$a;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, La/b/o/i/l;->a()La/b/o/i/k;

    move-result-object v1

    :cond_0
    return-object v1
.end method

.method public c()Z
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/ActionMenuItemView$a;->k:Landroidx/appcompat/view/menu/ActionMenuItemView;

    iget-object v1, v0, Landroidx/appcompat/view/menu/ActionMenuItemView;->i:La/b/o/i/g$b;

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    iget-object v0, v0, Landroidx/appcompat/view/menu/ActionMenuItemView;->f:La/b/o/i/i;

    invoke-interface {v1, v0}, La/b/o/i/g$b;->b(La/b/o/i/i;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ActionMenuItemView$a;->b()La/b/o/i/p;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-interface {v0}, La/b/o/i/p;->a()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v2, 0x1

    :cond_0
    return v2
.end method
