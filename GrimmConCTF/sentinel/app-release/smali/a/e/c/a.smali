.class public La/e/c/a;
.super La/e/c/c;
.source ""


# instance fields
.field public j:I

.field public k:I

.field public l:La/e/b/h/a;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 0

    invoke-direct {p0, p1}, La/e/c/c;-><init>(Landroid/content/Context;)V

    const/16 p1, 0x8

    invoke-super {p0, p1}, Landroid/view/View;->setVisibility(I)V

    return-void
.end method


# virtual methods
.method public f(Landroid/util/AttributeSet;)V
    .locals 0

    const/4 p1, 0x0

    invoke-super {p0, p1}, La/e/c/c;->f(Landroid/util/AttributeSet;)V

    new-instance p1, La/e/b/h/a;

    invoke-direct {p1}, La/e/b/h/a;-><init>()V

    iput-object p1, p0, La/e/c/a;->l:La/e/b/h/a;

    .line 1
    iput-object p1, p0, La/e/c/c;->e:La/e/b/h/g;

    invoke-virtual {p0}, La/e/c/c;->j()V

    return-void
.end method

.method public getMargin()I
    .locals 1

    iget-object v0, p0, La/e/c/a;->l:La/e/b/h/a;

    .line 1
    iget v0, v0, La/e/b/h/a;->s0:I

    return v0
.end method

.method public getType()I
    .locals 1

    iget v0, p0, La/e/c/a;->j:I

    return v0
.end method

.method public setAllowsGoneWidget(Z)V
    .locals 1

    iget-object v0, p0, La/e/c/a;->l:La/e/b/h/a;

    .line 1
    iput-boolean p1, v0, La/e/b/h/a;->r0:Z

    return-void
.end method

.method public setDpMargin(I)V
    .locals 1

    invoke-virtual {p0}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v0

    iget v0, v0, Landroid/util/DisplayMetrics;->density:F

    int-to-float p1, p1

    mul-float/2addr p1, v0

    const/high16 v0, 0x3f000000    # 0.5f

    add-float/2addr p1, v0

    float-to-int p1, p1

    iget-object v0, p0, La/e/c/a;->l:La/e/b/h/a;

    .line 1
    iput p1, v0, La/e/b/h/a;->s0:I

    return-void
.end method

.method public setMargin(I)V
    .locals 1

    iget-object v0, p0, La/e/c/a;->l:La/e/b/h/a;

    .line 1
    iput p1, v0, La/e/b/h/a;->s0:I

    return-void
.end method

.method public setType(I)V
    .locals 0

    iput p1, p0, La/e/c/a;->j:I

    return-void
.end method
