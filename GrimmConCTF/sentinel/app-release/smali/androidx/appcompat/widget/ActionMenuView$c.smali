.class public Landroidx/appcompat/widget/ActionMenuView$c;
.super La/b/p/i0$a;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/widget/ActionMenuView;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "c"
.end annotation


# instance fields
.field public c:Z
    .annotation runtime Landroid/view/ViewDebug$ExportedProperty;
    .end annotation
.end field

.field public d:I
    .annotation runtime Landroid/view/ViewDebug$ExportedProperty;
    .end annotation
.end field

.field public e:I
    .annotation runtime Landroid/view/ViewDebug$ExportedProperty;
    .end annotation
.end field

.field public f:Z
    .annotation runtime Landroid/view/ViewDebug$ExportedProperty;
    .end annotation
.end field

.field public g:Z
    .annotation runtime Landroid/view/ViewDebug$ExportedProperty;
    .end annotation
.end field

.field public h:Z


# direct methods
.method public constructor <init>(II)V
    .locals 0

    invoke-direct {p0, p1, p2}, La/b/p/i0$a;-><init>(II)V

    const/4 p1, 0x0

    iput-boolean p1, p0, Landroidx/appcompat/widget/ActionMenuView$c;->c:Z

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 0

    invoke-direct {p0, p1, p2}, La/b/p/i0$a;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    return-void
.end method

.method public constructor <init>(Landroid/view/ViewGroup$LayoutParams;)V
    .locals 0

    invoke-direct {p0, p1}, La/b/p/i0$a;-><init>(Landroid/view/ViewGroup$LayoutParams;)V

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/widget/ActionMenuView$c;)V
    .locals 0

    invoke-direct {p0, p1}, La/b/p/i0$a;-><init>(Landroid/view/ViewGroup$LayoutParams;)V

    iget-boolean p1, p1, Landroidx/appcompat/widget/ActionMenuView$c;->c:Z

    iput-boolean p1, p0, Landroidx/appcompat/widget/ActionMenuView$c;->c:Z

    return-void
.end method
