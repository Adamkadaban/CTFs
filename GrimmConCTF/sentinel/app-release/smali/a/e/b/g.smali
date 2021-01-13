.class public La/e/b/g;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/e/b/g$a;
    }
.end annotation


# static fields
.field public static q:I = 0x1


# instance fields
.field public a:Z

.field public b:Ljava/lang/String;

.field public c:I

.field public d:I

.field public e:I

.field public f:F

.field public g:Z

.field public h:[F

.field public i:[F

.field public j:La/e/b/g$a;

.field public k:[La/e/b/b;

.field public l:I

.field public m:I

.field public n:Z

.field public o:I

.field public p:F


# direct methods
.method public constructor <init>(La/e/b/g$a;)V
    .locals 4

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, -0x1

    iput v0, p0, La/e/b/g;->c:I

    iput v0, p0, La/e/b/g;->d:I

    const/4 v1, 0x0

    iput v1, p0, La/e/b/g;->e:I

    iput-boolean v1, p0, La/e/b/g;->g:Z

    const/16 v2, 0x9

    new-array v3, v2, [F

    iput-object v3, p0, La/e/b/g;->h:[F

    new-array v2, v2, [F

    iput-object v2, p0, La/e/b/g;->i:[F

    const/16 v2, 0x10

    new-array v2, v2, [La/e/b/b;

    iput-object v2, p0, La/e/b/g;->k:[La/e/b/b;

    iput v1, p0, La/e/b/g;->l:I

    iput v1, p0, La/e/b/g;->m:I

    iput-boolean v1, p0, La/e/b/g;->n:Z

    iput v0, p0, La/e/b/g;->o:I

    const/4 v0, 0x0

    iput v0, p0, La/e/b/g;->p:F

    iput-object p1, p0, La/e/b/g;->j:La/e/b/g$a;

    return-void
.end method


# virtual methods
.method public final a(La/e/b/b;)V
    .locals 3

    const/4 v0, 0x0

    :goto_0
    iget v1, p0, La/e/b/g;->l:I

    if-ge v0, v1, :cond_1

    iget-object v1, p0, La/e/b/g;->k:[La/e/b/b;

    aget-object v1, v1, v0

    if-ne v1, p1, :cond_0

    return-void

    :cond_0
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    iget-object v0, p0, La/e/b/g;->k:[La/e/b/b;

    array-length v2, v0

    if-lt v1, v2, :cond_2

    array-length v1, v0

    mul-int/lit8 v1, v1, 0x2

    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [La/e/b/b;

    iput-object v0, p0, La/e/b/g;->k:[La/e/b/b;

    :cond_2
    iget-object v0, p0, La/e/b/g;->k:[La/e/b/b;

    iget v1, p0, La/e/b/g;->l:I

    aput-object p1, v0, v1

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, La/e/b/g;->l:I

    return-void
.end method

.method public final b(La/e/b/b;)V
    .locals 4

    iget v0, p0, La/e/b/g;->l:I

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_2

    iget-object v2, p0, La/e/b/g;->k:[La/e/b/b;

    aget-object v2, v2, v1

    if-ne v2, p1, :cond_1

    :goto_1
    add-int/lit8 p1, v0, -0x1

    if-ge v1, p1, :cond_0

    iget-object p1, p0, La/e/b/g;->k:[La/e/b/b;

    add-int/lit8 v2, v1, 0x1

    aget-object v3, p1, v2

    aput-object v3, p1, v1

    move v1, v2

    goto :goto_1

    :cond_0
    iget p1, p0, La/e/b/g;->l:I

    add-int/lit8 p1, p1, -0x1

    iput p1, p0, La/e/b/g;->l:I

    return-void

    :cond_1
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_2
    return-void
.end method

.method public c()V
    .locals 6

    const/4 v0, 0x0

    iput-object v0, p0, La/e/b/g;->b:Ljava/lang/String;

    sget-object v1, La/e/b/g$a;->f:La/e/b/g$a;

    iput-object v1, p0, La/e/b/g;->j:La/e/b/g$a;

    const/4 v1, 0x0

    iput v1, p0, La/e/b/g;->e:I

    const/4 v2, -0x1

    iput v2, p0, La/e/b/g;->c:I

    iput v2, p0, La/e/b/g;->d:I

    const/4 v3, 0x0

    iput v3, p0, La/e/b/g;->f:F

    iput-boolean v1, p0, La/e/b/g;->g:Z

    iput-boolean v1, p0, La/e/b/g;->n:Z

    iput v2, p0, La/e/b/g;->o:I

    iput v3, p0, La/e/b/g;->p:F

    iget v2, p0, La/e/b/g;->l:I

    move v4, v1

    :goto_0
    if-ge v4, v2, :cond_0

    iget-object v5, p0, La/e/b/g;->k:[La/e/b/b;

    aput-object v0, v5, v4

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_0
    iput v1, p0, La/e/b/g;->l:I

    iput v1, p0, La/e/b/g;->m:I

    iput-boolean v1, p0, La/e/b/g;->a:Z

    iget-object v0, p0, La/e/b/g;->i:[F

    invoke-static {v0, v3}, Ljava/util/Arrays;->fill([FF)V

    return-void
.end method

.method public d(La/e/b/d;F)V
    .locals 3

    iput p2, p0, La/e/b/g;->f:F

    const/4 p2, 0x1

    iput-boolean p2, p0, La/e/b/g;->g:Z

    const/4 p2, 0x0

    iput-boolean p2, p0, La/e/b/g;->n:Z

    const/4 v0, -0x1

    iput v0, p0, La/e/b/g;->o:I

    const/4 v1, 0x0

    iput v1, p0, La/e/b/g;->p:F

    iget v1, p0, La/e/b/g;->l:I

    iput v0, p0, La/e/b/g;->d:I

    move v0, p2

    :goto_0
    if-ge v0, v1, :cond_0

    iget-object v2, p0, La/e/b/g;->k:[La/e/b/b;

    aget-object v2, v2, v0

    invoke-virtual {v2, p1, p0, p2}, La/e/b/b;->k(La/e/b/d;La/e/b/g;Z)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    iput p2, p0, La/e/b/g;->l:I

    return-void
.end method

.method public final e(La/e/b/d;La/e/b/b;)V
    .locals 4

    iget v0, p0, La/e/b/g;->l:I

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    if-ge v2, v0, :cond_0

    iget-object v3, p0, La/e/b/g;->k:[La/e/b/b;

    aget-object v3, v3, v2

    invoke-virtual {v3, p1, p2, v1}, La/e/b/b;->l(La/e/b/d;La/e/b/b;Z)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_0
    iput v1, p0, La/e/b/g;->l:I

    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    iget-object v0, p0, La/e/b/g;->b:Ljava/lang/String;

    const-string v1, ""

    if-eqz v0, :cond_0

    invoke-static {v1}, Lb/a/a/a/a;->b(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    iget-object v1, p0, La/e/b/g;->b:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_0

    :cond_0
    invoke-static {v1}, Lb/a/a/a/a;->b(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    iget v1, p0, La/e/b/g;->c:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    :goto_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
