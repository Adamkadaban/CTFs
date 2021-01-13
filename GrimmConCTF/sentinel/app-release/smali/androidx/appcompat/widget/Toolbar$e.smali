.class public Landroidx/appcompat/widget/Toolbar$e;
.super La/b/k/a$a;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/widget/Toolbar;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "e"
.end annotation


# instance fields
.field public b:I


# direct methods
.method public constructor <init>(II)V
    .locals 0

    invoke-direct {p0, p1, p2}, La/b/k/a$a;-><init>(II)V

    const/4 p1, 0x0

    iput p1, p0, Landroidx/appcompat/widget/Toolbar$e;->b:I

    const p1, 0x800013

    iput p1, p0, La/b/k/a$a;->a:I

    return-void
.end method

.method public constructor <init>(La/b/k/a$a;)V
    .locals 0

    invoke-direct {p0, p1}, La/b/k/a$a;-><init>(La/b/k/a$a;)V

    const/4 p1, 0x0

    iput p1, p0, Landroidx/appcompat/widget/Toolbar$e;->b:I

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 0

    invoke-direct {p0, p1, p2}, La/b/k/a$a;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    const/4 p1, 0x0

    iput p1, p0, Landroidx/appcompat/widget/Toolbar$e;->b:I

    return-void
.end method

.method public constructor <init>(Landroid/view/ViewGroup$LayoutParams;)V
    .locals 0

    invoke-direct {p0, p1}, La/b/k/a$a;-><init>(Landroid/view/ViewGroup$LayoutParams;)V

    const/4 p1, 0x0

    iput p1, p0, Landroidx/appcompat/widget/Toolbar$e;->b:I

    return-void
.end method

.method public constructor <init>(Landroid/view/ViewGroup$MarginLayoutParams;)V
    .locals 1

    invoke-direct {p0, p1}, La/b/k/a$a;-><init>(Landroid/view/ViewGroup$LayoutParams;)V

    const/4 v0, 0x0

    iput v0, p0, Landroidx/appcompat/widget/Toolbar$e;->b:I

    .line 1
    iget v0, p1, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    iput v0, p0, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    iget v0, p1, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    iput v0, p0, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    iget v0, p1, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    iput v0, p0, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    iget p1, p1, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    iput p1, p0, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/widget/Toolbar$e;)V
    .locals 1

    invoke-direct {p0, p1}, La/b/k/a$a;-><init>(La/b/k/a$a;)V

    const/4 v0, 0x0

    iput v0, p0, Landroidx/appcompat/widget/Toolbar$e;->b:I

    iget p1, p1, Landroidx/appcompat/widget/Toolbar$e;->b:I

    iput p1, p0, Landroidx/appcompat/widget/Toolbar$e;->b:I

    return-void
.end method
