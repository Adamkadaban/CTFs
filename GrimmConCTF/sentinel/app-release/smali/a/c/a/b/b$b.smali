.class public La/c/a/b/b$b;
.super La/c/a/b/b$e;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/c/a/b/b;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "b"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<K:",
        "Ljava/lang/Object;",
        "V:",
        "Ljava/lang/Object;",
        ">",
        "La/c/a/b/b$e<",
        "TK;TV;>;"
    }
.end annotation


# direct methods
.method public constructor <init>(La/c/a/b/b$c;La/c/a/b/b$c;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/c/a/b/b$c<",
            "TK;TV;>;",
            "La/c/a/b/b$c<",
            "TK;TV;>;)V"
        }
    .end annotation

    invoke-direct {p0, p1, p2}, La/c/a/b/b$e;-><init>(La/c/a/b/b$c;La/c/a/b/b$c;)V

    return-void
.end method


# virtual methods
.method public b(La/c/a/b/b$c;)La/c/a/b/b$c;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/c/a/b/b$c<",
            "TK;TV;>;)",
            "La/c/a/b/b$c<",
            "TK;TV;>;"
        }
    .end annotation

    iget-object p1, p1, La/c/a/b/b$c;->d:La/c/a/b/b$c;

    return-object p1
.end method

.method public c(La/c/a/b/b$c;)La/c/a/b/b$c;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/c/a/b/b$c<",
            "TK;TV;>;)",
            "La/c/a/b/b$c<",
            "TK;TV;>;"
        }
    .end annotation

    iget-object p1, p1, La/c/a/b/b$c;->e:La/c/a/b/b$c;

    return-object p1
.end method
