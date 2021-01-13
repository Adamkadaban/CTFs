.class public La/n/b;
.super La/n/a;
.source ""


# instance fields
.field public final d:Landroid/util/SparseIntArray;

.field public final e:Landroid/os/Parcel;

.field public final f:I

.field public final g:I

.field public final h:Ljava/lang/String;

.field public i:I

.field public j:I

.field public k:I


# direct methods
.method public constructor <init>(Landroid/os/Parcel;)V
    .locals 8

    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    move-result v2

    invoke-virtual {p1}, Landroid/os/Parcel;->dataSize()I

    move-result v3

    new-instance v5, La/d/a;

    invoke-direct {v5}, La/d/a;-><init>()V

    new-instance v6, La/d/a;

    invoke-direct {v6}, La/d/a;-><init>()V

    new-instance v7, La/d/a;

    invoke-direct {v7}, La/d/a;-><init>()V

    const-string v4, ""

    move-object v0, p0

    move-object v1, p1

    invoke-direct/range {v0 .. v7}, La/n/b;-><init>(Landroid/os/Parcel;IILjava/lang/String;La/d/a;La/d/a;La/d/a;)V

    return-void
.end method

.method public constructor <init>(Landroid/os/Parcel;IILjava/lang/String;La/d/a;La/d/a;La/d/a;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/os/Parcel;",
            "II",
            "Ljava/lang/String;",
            "La/d/a<",
            "Ljava/lang/String;",
            "Ljava/lang/reflect/Method;",
            ">;",
            "La/d/a<",
            "Ljava/lang/String;",
            "Ljava/lang/reflect/Method;",
            ">;",
            "La/d/a<",
            "Ljava/lang/String;",
            "Ljava/lang/Class;",
            ">;)V"
        }
    .end annotation

    invoke-direct {p0, p5, p6, p7}, La/n/a;-><init>(La/d/a;La/d/a;La/d/a;)V

    new-instance p5, Landroid/util/SparseIntArray;

    invoke-direct {p5}, Landroid/util/SparseIntArray;-><init>()V

    iput-object p5, p0, La/n/b;->d:Landroid/util/SparseIntArray;

    const/4 p5, -0x1

    iput p5, p0, La/n/b;->i:I

    const/4 p6, 0x0

    iput p6, p0, La/n/b;->j:I

    iput p5, p0, La/n/b;->k:I

    iput-object p1, p0, La/n/b;->e:Landroid/os/Parcel;

    iput p2, p0, La/n/b;->f:I

    iput p3, p0, La/n/b;->g:I

    iput p2, p0, La/n/b;->j:I

    iput-object p4, p0, La/n/b;->h:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public a()V
    .locals 4

    iget v0, p0, La/n/b;->i:I

    if-ltz v0, :cond_0

    iget-object v1, p0, La/n/b;->d:Landroid/util/SparseIntArray;

    invoke-virtual {v1, v0}, Landroid/util/SparseIntArray;->get(I)I

    move-result v0

    iget-object v1, p0, La/n/b;->e:Landroid/os/Parcel;

    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    move-result v1

    sub-int v2, v1, v0

    iget-object v3, p0, La/n/b;->e:Landroid/os/Parcel;

    invoke-virtual {v3, v0}, Landroid/os/Parcel;->setDataPosition(I)V

    iget-object v0, p0, La/n/b;->e:Landroid/os/Parcel;

    invoke-virtual {v0, v2}, Landroid/os/Parcel;->writeInt(I)V

    iget-object v0, p0, La/n/b;->e:Landroid/os/Parcel;

    invoke-virtual {v0, v1}, Landroid/os/Parcel;->setDataPosition(I)V

    :cond_0
    return-void
.end method

.method public b()La/n/a;
    .locals 9

    new-instance v8, La/n/b;

    iget-object v1, p0, La/n/b;->e:Landroid/os/Parcel;

    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    move-result v2

    iget v0, p0, La/n/b;->j:I

    iget v3, p0, La/n/b;->f:I

    if-ne v0, v3, :cond_0

    iget v0, p0, La/n/b;->g:I

    :cond_0
    move v3, v0

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v4, p0, La/n/b;->h:Ljava/lang/String;

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, "  "

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    iget-object v5, p0, La/n/a;->a:La/d/a;

    iget-object v6, p0, La/n/a;->b:La/d/a;

    iget-object v7, p0, La/n/a;->c:La/d/a;

    move-object v0, v8

    invoke-direct/range {v0 .. v7}, La/n/b;-><init>(Landroid/os/Parcel;IILjava/lang/String;La/d/a;La/d/a;La/d/a;)V

    return-object v8
.end method

.method public h(I)Z
    .locals 4

    :goto_0
    iget v0, p0, La/n/b;->j:I

    iget v1, p0, La/n/b;->g:I

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-ge v0, v1, :cond_2

    iget v0, p0, La/n/b;->k:I

    if-ne v0, p1, :cond_0

    return v2

    :cond_0
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v0

    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    move-result v0

    if-lez v0, :cond_1

    return v3

    :cond_1
    iget-object v0, p0, La/n/b;->e:Landroid/os/Parcel;

    iget v1, p0, La/n/b;->j:I

    invoke-virtual {v0, v1}, Landroid/os/Parcel;->setDataPosition(I)V

    iget-object v0, p0, La/n/b;->e:Landroid/os/Parcel;

    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    move-result v0

    iget-object v1, p0, La/n/b;->e:Landroid/os/Parcel;

    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    move-result v1

    iput v1, p0, La/n/b;->k:I

    iget v1, p0, La/n/b;->j:I

    add-int/2addr v1, v0

    iput v1, p0, La/n/b;->j:I

    goto :goto_0

    :cond_2
    iget v0, p0, La/n/b;->k:I

    if-ne v0, p1, :cond_3

    goto :goto_1

    :cond_3
    move v2, v3

    :goto_1
    return v2
.end method

.method public l(I)V
    .locals 2

    invoke-virtual {p0}, La/n/b;->a()V

    iput p1, p0, La/n/b;->i:I

    iget-object v0, p0, La/n/b;->d:Landroid/util/SparseIntArray;

    iget-object v1, p0, La/n/b;->e:Landroid/os/Parcel;

    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    move-result v1

    invoke-virtual {v0, p1, v1}, Landroid/util/SparseIntArray;->put(II)V

    .line 1
    iget-object v0, p0, La/n/b;->e:Landroid/os/Parcel;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/os/Parcel;->writeInt(I)V

    iget-object v0, p0, La/n/b;->e:Landroid/os/Parcel;

    invoke-virtual {v0, p1}, Landroid/os/Parcel;->writeInt(I)V

    return-void
.end method
