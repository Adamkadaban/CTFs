.class public La/k/a/b$c;
.super La/j/p;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/k/a/b;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "c"
.end annotation


# static fields
.field public static final c:La/j/q;


# instance fields
.field public b:La/d/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "La/d/i<",
            "La/k/a/b$a;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public static constructor <clinit>()V
    .locals 1

    new-instance v0, La/k/a/b$c$a;

    invoke-direct {v0}, La/k/a/b$c$a;-><init>()V

    sput-object v0, La/k/a/b$c;->c:La/j/q;

    return-void
.end method

.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, La/j/p;-><init>()V

    new-instance v0, La/d/i;

    const/16 v1, 0xa

    .line 1
    invoke-direct {v0, v1}, La/d/i;-><init>(I)V

    .line 2
    iput-object v0, p0, La/k/a/b$c;->b:La/d/i;

    return-void
.end method


# virtual methods
.method public a()V
    .locals 6

    iget-object v0, p0, La/k/a/b$c;->b:La/d/i;

    invoke-virtual {v0}, La/d/i;->i()I

    move-result v0

    const/4 v1, 0x0

    const/4 v2, 0x0

    if-lez v0, :cond_0

    iget-object v0, p0, La/k/a/b$c;->b:La/d/i;

    invoke-virtual {v0, v1}, La/d/i;->j(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/k/a/b$a;

    .line 1
    throw v2

    .line 2
    :cond_0
    iget-object v0, p0, La/k/a/b$c;->b:La/d/i;

    .line 3
    iget v3, v0, La/d/i;->e:I

    iget-object v4, v0, La/d/i;->d:[Ljava/lang/Object;

    move v5, v1

    :goto_0
    if-ge v5, v3, :cond_1

    aput-object v2, v4, v5

    add-int/lit8 v5, v5, 0x1

    goto :goto_0

    :cond_1
    iput v1, v0, La/d/i;->e:I

    iput-boolean v1, v0, La/d/i;->b:Z

    return-void
.end method
