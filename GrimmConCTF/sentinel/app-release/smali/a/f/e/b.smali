.class public final La/f/e/b;
.super Ljava/lang/Object;
.source ""


# static fields
.field public static final e:La/f/e/b;


# instance fields
.field public final a:I

.field public final b:I

.field public final c:I

.field public final d:I


# direct methods
.method public static constructor <clinit>()V
    .locals 2

    new-instance v0, La/f/e/b;

    const/4 v1, 0x0

    invoke-direct {v0, v1, v1, v1, v1}, La/f/e/b;-><init>(IIII)V

    sput-object v0, La/f/e/b;->e:La/f/e/b;

    return-void
.end method

.method public constructor <init>(IIII)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, La/f/e/b;->a:I

    iput p2, p0, La/f/e/b;->b:I

    iput p3, p0, La/f/e/b;->c:I

    iput p4, p0, La/f/e/b;->d:I

    return-void
.end method

.method public static a(IIII)La/f/e/b;
    .locals 1

    if-nez p0, :cond_0

    if-nez p1, :cond_0

    if-nez p2, :cond_0

    if-nez p3, :cond_0

    sget-object p0, La/f/e/b;->e:La/f/e/b;

    return-object p0

    :cond_0
    new-instance v0, La/f/e/b;

    invoke-direct {v0, p0, p1, p2, p3}, La/f/e/b;-><init>(IIII)V

    return-object v0
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 4

    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    const/4 v1, 0x0

    if-eqz p1, :cond_6

    const-class v2, La/f/e/b;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    if-eq v2, v3, :cond_1

    goto :goto_0

    :cond_1
    check-cast p1, La/f/e/b;

    iget v2, p0, La/f/e/b;->d:I

    iget v3, p1, La/f/e/b;->d:I

    if-eq v2, v3, :cond_2

    return v1

    :cond_2
    iget v2, p0, La/f/e/b;->a:I

    iget v3, p1, La/f/e/b;->a:I

    if-eq v2, v3, :cond_3

    return v1

    :cond_3
    iget v2, p0, La/f/e/b;->c:I

    iget v3, p1, La/f/e/b;->c:I

    if-eq v2, v3, :cond_4

    return v1

    :cond_4
    iget v2, p0, La/f/e/b;->b:I

    iget p1, p1, La/f/e/b;->b:I

    if-eq v2, p1, :cond_5

    return v1

    :cond_5
    return v0

    :cond_6
    :goto_0
    return v1
.end method

.method public hashCode()I
    .locals 2

    iget v0, p0, La/f/e/b;->a:I

    mul-int/lit8 v0, v0, 0x1f

    iget v1, p0, La/f/e/b;->b:I

    add-int/2addr v0, v1

    mul-int/lit8 v0, v0, 0x1f

    iget v1, p0, La/f/e/b;->c:I

    add-int/2addr v0, v1

    mul-int/lit8 v0, v0, 0x1f

    iget v1, p0, La/f/e/b;->d:I

    add-int/2addr v0, v1

    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    const-string v0, "Insets{left="

    invoke-static {v0}, Lb/a/a/a/a;->b(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    iget v1, p0, La/f/e/b;->a:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ", top="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, La/f/e/b;->b:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ", right="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, La/f/e/b;->c:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ", bottom="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, La/f/e/b;->d:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const/16 v1, 0x7d

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
