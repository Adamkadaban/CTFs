.class public La/b/k/r$b;
.super La/f/j/r;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/b/k/r;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:La/b/k/r;


# direct methods
.method public constructor <init>(La/b/k/r;)V
    .locals 0

    iput-object p1, p0, La/b/k/r$b;->a:La/b/k/r;

    invoke-direct {p0}, La/f/j/r;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Landroid/view/View;)V
    .locals 1

    iget-object p1, p0, La/b/k/r$b;->a:La/b/k/r;

    const/4 v0, 0x0

    iput-object v0, p1, La/b/k/r;->u:La/b/o/g;

    iget-object p1, p1, La/b/k/r;->d:Landroidx/appcompat/widget/ActionBarContainer;

    invoke-virtual {p1}, Landroid/widget/FrameLayout;->requestLayout()V

    return-void
.end method
