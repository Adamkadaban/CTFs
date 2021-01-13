.class public La/e/c/e$d;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/e/c/e;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "d"
.end annotation


# instance fields
.field public a:Z

.field public b:I

.field public c:I

.field public d:F

.field public e:F


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-boolean v0, p0, La/e/c/e$d;->a:Z

    iput v0, p0, La/e/c/e$d;->b:I

    iput v0, p0, La/e/c/e$d;->c:I

    const/high16 v0, 0x3f800000    # 1.0f

    iput v0, p0, La/e/c/e$d;->d:F

    const/high16 v0, 0x7fc00000    # Float.NaN

    iput v0, p0, La/e/c/e$d;->e:F

    return-void
.end method


# virtual methods
.method public a(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 3

    sget-object v0, La/e/c/k;->PropertySet:[I

    invoke-virtual {p1, p2, v0}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object p1

    const/4 p2, 0x1

    iput-boolean p2, p0, La/e/c/e$d;->a:Z

    invoke-virtual {p1}, Landroid/content/res/TypedArray;->getIndexCount()I

    move-result p2

    const/4 v0, 0x0

    :goto_0
    if-ge v0, p2, :cond_4

    invoke-virtual {p1, v0}, Landroid/content/res/TypedArray;->getIndex(I)I

    move-result v1

    sget v2, La/e/c/k;->PropertySet_android_alpha:I

    if-ne v1, v2, :cond_0

    iget v2, p0, La/e/c/e$d;->d:F

    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v1

    iput v1, p0, La/e/c/e$d;->d:F

    goto :goto_1

    :cond_0
    sget v2, La/e/c/k;->PropertySet_android_visibility:I

    if-ne v1, v2, :cond_1

    iget v2, p0, La/e/c/e$d;->b:I

    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v1

    iput v1, p0, La/e/c/e$d;->b:I

    .line 1
    sget-object v2, La/e/c/e;->d:[I

    .line 2
    aget v1, v2, v1

    iput v1, p0, La/e/c/e$d;->b:I

    goto :goto_1

    :cond_1
    sget v2, La/e/c/k;->PropertySet_visibilityMode:I

    if-ne v1, v2, :cond_2

    iget v2, p0, La/e/c/e$d;->c:I

    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v1

    iput v1, p0, La/e/c/e$d;->c:I

    goto :goto_1

    :cond_2
    sget v2, La/e/c/k;->PropertySet_motionProgress:I

    if-ne v1, v2, :cond_3

    iget v2, p0, La/e/c/e$d;->e:F

    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v1

    iput v1, p0, La/e/c/e$d;->e:F

    :cond_3
    :goto_1
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_4
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    return-void
.end method
