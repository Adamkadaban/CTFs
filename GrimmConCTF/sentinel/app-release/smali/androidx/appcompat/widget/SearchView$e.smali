.class public Landroidx/appcompat/widget/SearchView$e;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements Landroid/view/View$OnLayoutChangeListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/widget/SearchView;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:Landroidx/appcompat/widget/SearchView;


# direct methods
.method public constructor <init>(Landroidx/appcompat/widget/SearchView;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/widget/SearchView$e;->a:Landroidx/appcompat/widget/SearchView;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onLayoutChange(Landroid/view/View;IIIIIIII)V
    .locals 0

    iget-object p1, p0, Landroidx/appcompat/widget/SearchView$e;->a:Landroidx/appcompat/widget/SearchView;

    .line 1
    iget-object p2, p1, Landroidx/appcompat/widget/SearchView;->y:Landroid/view/View;

    invoke-virtual {p2}, Landroid/view/View;->getWidth()I

    move-result p2

    const/4 p3, 0x1

    if-le p2, p3, :cond_2

    invoke-virtual {p1}, Landroid/view/ViewGroup;->getContext()Landroid/content/Context;

    move-result-object p2

    invoke-virtual {p2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p2

    iget-object p3, p1, Landroidx/appcompat/widget/SearchView;->s:Landroid/view/View;

    invoke-virtual {p3}, Landroid/view/View;->getPaddingLeft()I

    move-result p3

    new-instance p4, Landroid/graphics/Rect;

    invoke-direct {p4}, Landroid/graphics/Rect;-><init>()V

    invoke-static {p1}, La/b/p/d1;->b(Landroid/view/View;)Z

    move-result p5

    iget-boolean p6, p1, Landroidx/appcompat/widget/SearchView;->Q:Z

    if-eqz p6, :cond_0

    sget p6, La/b/d;->abc_dropdownitem_icon_width:I

    invoke-virtual {p2, p6}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result p6

    sget p7, La/b/d;->abc_dropdownitem_text_padding_left:I

    invoke-virtual {p2, p7}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result p2

    add-int/2addr p2, p6

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    iget-object p6, p1, Landroidx/appcompat/widget/SearchView;->q:Landroidx/appcompat/widget/SearchView$SearchAutoComplete;

    invoke-virtual {p6}, Landroid/widget/AutoCompleteTextView;->getDropDownBackground()Landroid/graphics/drawable/Drawable;

    move-result-object p6

    invoke-virtual {p6, p4}, Landroid/graphics/drawable/Drawable;->getPadding(Landroid/graphics/Rect;)Z

    if-eqz p5, :cond_1

    iget p5, p4, Landroid/graphics/Rect;->left:I

    neg-int p5, p5

    goto :goto_1

    :cond_1
    iget p5, p4, Landroid/graphics/Rect;->left:I

    add-int/2addr p5, p2

    sub-int p5, p3, p5

    :goto_1
    iget-object p6, p1, Landroidx/appcompat/widget/SearchView;->q:Landroidx/appcompat/widget/SearchView$SearchAutoComplete;

    invoke-virtual {p6, p5}, Landroid/widget/AutoCompleteTextView;->setDropDownHorizontalOffset(I)V

    iget-object p5, p1, Landroidx/appcompat/widget/SearchView;->y:Landroid/view/View;

    invoke-virtual {p5}, Landroid/view/View;->getWidth()I

    move-result p5

    iget p6, p4, Landroid/graphics/Rect;->left:I

    add-int/2addr p5, p6

    iget p4, p4, Landroid/graphics/Rect;->right:I

    add-int/2addr p5, p4

    add-int/2addr p5, p2

    sub-int/2addr p5, p3

    iget-object p1, p1, Landroidx/appcompat/widget/SearchView;->q:Landroidx/appcompat/widget/SearchView$SearchAutoComplete;

    invoke-virtual {p1, p5}, Landroid/widget/AutoCompleteTextView;->setDropDownWidth(I)V

    :cond_2
    return-void
.end method
