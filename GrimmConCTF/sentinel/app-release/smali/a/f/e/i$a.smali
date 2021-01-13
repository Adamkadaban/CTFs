.class public La/f/e/i$a;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements La/f/e/i$b;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = La/f/e/i;->f([La/f/g/b$f;I)La/f/g/b$f;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "La/f/e/i$b<",
        "La/f/g/b$f;",
        ">;"
    }
.end annotation


# direct methods
.method public constructor <init>(La/f/e/i;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Ljava/lang/Object;)I
    .locals 0

    check-cast p1, La/f/g/b$f;

    .line 1
    iget p1, p1, La/f/g/b$f;->c:I

    return p1
.end method

.method public b(Ljava/lang/Object;)Z
    .locals 0

    check-cast p1, La/f/g/b$f;

    .line 1
    iget-boolean p1, p1, La/f/g/b$f;->d:Z

    return p1
.end method
