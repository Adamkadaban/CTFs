.class public La/e/c/d$b;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/e/c/d;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "b"
.end annotation


# instance fields
.field public a:F

.field public b:F

.field public c:F

.field public d:F

.field public e:I

.field public f:La/e/c/e;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lorg/xmlpull/v1/XmlPullParser;)V
    .locals 5

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/high16 v0, 0x7fc00000    # Float.NaN

    iput v0, p0, La/e/c/d$b;->a:F

    iput v0, p0, La/e/c/d$b;->b:F

    iput v0, p0, La/e/c/d$b;->c:F

    iput v0, p0, La/e/c/d$b;->d:F

    const/4 v0, -0x1

    iput v0, p0, La/e/c/d$b;->e:I

    invoke-static {p2}, Landroid/util/Xml;->asAttributeSet(Lorg/xmlpull/v1/XmlPullParser;)Landroid/util/AttributeSet;

    move-result-object p2

    sget-object v0, La/e/c/k;->Variant:[I

    invoke-virtual {p1, p2, v0}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object p2

    invoke-virtual {p2}, Landroid/content/res/TypedArray;->getIndexCount()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_6

    invoke-virtual {p2, v1}, Landroid/content/res/TypedArray;->getIndex(I)I

    move-result v2

    sget v3, La/e/c/k;->Variant_constraints:I

    if-ne v2, v3, :cond_0

    iget v3, p0, La/e/c/d$b;->e:I

    invoke-virtual {p2, v2, v3}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v2

    iput v2, p0, La/e/c/d$b;->e:I

    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v2

    iget v3, p0, La/e/c/d$b;->e:I

    invoke-virtual {v2, v3}, Landroid/content/res/Resources;->getResourceTypeName(I)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v3

    iget v4, p0, La/e/c/d$b;->e:I

    invoke-virtual {v3, v4}, Landroid/content/res/Resources;->getResourceName(I)Ljava/lang/String;

    const-string v3, "layout"

    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_5

    new-instance v2, La/e/c/e;

    invoke-direct {v2}, La/e/c/e;-><init>()V

    iput-object v2, p0, La/e/c/d$b;->f:La/e/c/e;

    iget v3, p0, La/e/c/d$b;->e:I

    invoke-virtual {v2, p1, v3}, La/e/c/e;->b(Landroid/content/Context;I)V

    goto :goto_1

    :cond_0
    sget v3, La/e/c/k;->Variant_region_heightLessThan:I

    if-ne v2, v3, :cond_1

    iget v3, p0, La/e/c/d$b;->d:F

    invoke-virtual {p2, v2, v3}, Landroid/content/res/TypedArray;->getDimension(IF)F

    move-result v2

    iput v2, p0, La/e/c/d$b;->d:F

    goto :goto_1

    :cond_1
    sget v3, La/e/c/k;->Variant_region_heightMoreThan:I

    if-ne v2, v3, :cond_2

    iget v3, p0, La/e/c/d$b;->b:F

    invoke-virtual {p2, v2, v3}, Landroid/content/res/TypedArray;->getDimension(IF)F

    move-result v2

    iput v2, p0, La/e/c/d$b;->b:F

    goto :goto_1

    :cond_2
    sget v3, La/e/c/k;->Variant_region_widthLessThan:I

    if-ne v2, v3, :cond_3

    iget v3, p0, La/e/c/d$b;->c:F

    invoke-virtual {p2, v2, v3}, Landroid/content/res/TypedArray;->getDimension(IF)F

    move-result v2

    iput v2, p0, La/e/c/d$b;->c:F

    goto :goto_1

    :cond_3
    sget v3, La/e/c/k;->Variant_region_widthMoreThan:I

    if-ne v2, v3, :cond_4

    iget v3, p0, La/e/c/d$b;->a:F

    invoke-virtual {p2, v2, v3}, Landroid/content/res/TypedArray;->getDimension(IF)F

    move-result v2

    iput v2, p0, La/e/c/d$b;->a:F

    goto :goto_1

    :cond_4
    const-string v2, "ConstraintLayoutStates"

    const-string v3, "Unknown tag"

    invoke-static {v2, v3}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    :cond_5
    :goto_1
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_6
    invoke-virtual {p2}, Landroid/content/res/TypedArray;->recycle()V

    return-void
.end method
