.class public La/b/p/z0$a;
.super La/f/j/r;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = La/b/p/z0;->i(IJ)La/f/j/p;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public a:Z

.field public final synthetic b:I

.field public final synthetic c:La/b/p/z0;


# direct methods
.method public constructor <init>(La/b/p/z0;I)V
    .locals 0

    iput-object p1, p0, La/b/p/z0$a;->c:La/b/p/z0;

    iput p2, p0, La/b/p/z0$a;->b:I

    invoke-direct {p0}, La/f/j/r;-><init>()V

    const/4 p1, 0x0

    iput-boolean p1, p0, La/b/p/z0$a;->a:Z

    return-void
.end method


# virtual methods
.method public a(Landroid/view/View;)V
    .locals 1

    iget-boolean p1, p0, La/b/p/z0$a;->a:Z

    if-nez p1, :cond_0

    iget-object p1, p0, La/b/p/z0$a;->c:La/b/p/z0;

    iget-object p1, p1, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    iget v0, p0, La/b/p/z0$a;->b:I

    invoke-virtual {p1, v0}, Landroid/view/ViewGroup;->setVisibility(I)V

    :cond_0
    return-void
.end method

.method public b(Landroid/view/View;)V
    .locals 1

    iget-object p1, p0, La/b/p/z0$a;->c:La/b/p/z0;

    iget-object p1, p1, La/b/p/z0;->a:Landroidx/appcompat/widget/Toolbar;

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Landroid/view/ViewGroup;->setVisibility(I)V

    return-void
.end method

.method public c(Landroid/view/View;)V
    .locals 0

    const/4 p1, 0x1

    iput-boolean p1, p0, La/b/p/z0$a;->a:Z

    return-void
.end method
