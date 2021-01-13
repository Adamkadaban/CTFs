.class public La/e/b/h/i;
.super Ljava/lang/Object;
.source ""


# static fields
.field public static a:[Z


# direct methods
.method public static constructor <clinit>()V
    .locals 1

    const/4 v0, 0x3

    new-array v0, v0, [Z

    sput-object v0, La/e/b/h/i;->a:[Z

    return-void
.end method

.method public static a(La/e/b/h/e;La/e/b/d;La/e/b/h/d;)V
    .locals 7

    sget-object v0, La/e/b/h/d$a;->e:La/e/b/h/d$a;

    sget-object v1, La/e/b/h/d$a;->c:La/e/b/h/d$a;

    const/4 v2, -0x1

    iput v2, p2, La/e/b/h/d;->l:I

    iput v2, p2, La/e/b/h/d;->m:I

    iget-object v2, p0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v3, 0x0

    aget-object v2, v2, v3

    const/4 v4, 0x2

    if-eq v2, v1, :cond_0

    iget-object v2, p2, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v2, v2, v3

    if-ne v2, v0, :cond_0

    iget-object v2, p2, La/e/b/h/d;->F:La/e/b/h/c;

    iget v2, v2, La/e/b/h/c;->g:I

    invoke-virtual {p0}, La/e/b/h/d;->r()I

    move-result v3

    iget-object v5, p2, La/e/b/h/d;->H:La/e/b/h/c;

    iget v5, v5, La/e/b/h/c;->g:I

    sub-int/2addr v3, v5

    iget-object v5, p2, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {p1, v5}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v6

    iput-object v6, v5, La/e/b/h/c;->i:La/e/b/g;

    iget-object v5, p2, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {p1, v5}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v6

    iput-object v6, v5, La/e/b/h/c;->i:La/e/b/g;

    iget-object v5, p2, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v5, v5, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {p1, v5, v2}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object v5, p2, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v5, v5, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {p1, v5, v3}, La/e/b/d;->e(La/e/b/g;I)V

    iput v4, p2, La/e/b/h/d;->l:I

    .line 1
    iput v2, p2, La/e/b/h/d;->W:I

    sub-int/2addr v3, v2

    iput v3, p2, La/e/b/h/d;->S:I

    iget v2, p2, La/e/b/h/d;->Z:I

    if-ge v3, v2, :cond_0

    iput v2, p2, La/e/b/h/d;->S:I

    .line 2
    :cond_0
    iget-object v2, p0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v3, 0x1

    aget-object v2, v2, v3

    if-eq v2, v1, :cond_3

    iget-object v1, p2, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v1, v1, v3

    if-ne v1, v0, :cond_3

    iget-object v0, p2, La/e/b/h/d;->G:La/e/b/h/c;

    iget v0, v0, La/e/b/h/c;->g:I

    invoke-virtual {p0}, La/e/b/h/d;->l()I

    move-result p0

    iget-object v1, p2, La/e/b/h/d;->I:La/e/b/h/c;

    iget v1, v1, La/e/b/h/c;->g:I

    sub-int/2addr p0, v1

    iget-object v1, p2, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {p1, v1}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v2

    iput-object v2, v1, La/e/b/h/c;->i:La/e/b/g;

    iget-object v1, p2, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {p1, v1}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v2

    iput-object v2, v1, La/e/b/h/c;->i:La/e/b/g;

    iget-object v1, p2, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {p1, v1, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object v1, p2, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {p1, v1, p0}, La/e/b/d;->e(La/e/b/g;I)V

    iget v1, p2, La/e/b/h/d;->Y:I

    if-gtz v1, :cond_1

    .line 3
    iget v1, p2, La/e/b/h/d;->e0:I

    const/16 v2, 0x8

    if-ne v1, v2, :cond_2

    .line 4
    :cond_1
    iget-object v1, p2, La/e/b/h/d;->J:La/e/b/h/c;

    invoke-virtual {p1, v1}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v2

    iput-object v2, v1, La/e/b/h/c;->i:La/e/b/g;

    iget-object v1, p2, La/e/b/h/d;->J:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->i:La/e/b/g;

    iget v2, p2, La/e/b/h/d;->Y:I

    add-int/2addr v2, v0

    invoke-virtual {p1, v1, v2}, La/e/b/d;->e(La/e/b/g;I)V

    :cond_2
    iput v4, p2, La/e/b/h/d;->m:I

    .line 5
    iput v0, p2, La/e/b/h/d;->X:I

    sub-int/2addr p0, v0

    iput p0, p2, La/e/b/h/d;->T:I

    iget p1, p2, La/e/b/h/d;->a0:I

    if-ge p0, p1, :cond_3

    iput p1, p2, La/e/b/h/d;->T:I

    :cond_3
    return-void
.end method

.method public static final b(II)Z
    .locals 0

    and-int/2addr p0, p1

    if-ne p0, p1, :cond_0

    const/4 p0, 0x1

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    :goto_0
    return p0
.end method
