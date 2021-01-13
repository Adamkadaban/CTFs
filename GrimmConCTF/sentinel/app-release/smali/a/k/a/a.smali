.class public abstract La/k/a/a;
.super Ljava/lang/Object;
.source ""


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static b(La/j/g;)La/k/a/a;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T::",
            "La/j/g;",
            ":",
            "La/j/t;",
            ">(TT;)",
            "La/k/a/a;"
        }
    .end annotation

    new-instance v0, La/k/a/b;

    move-object v1, p0

    check-cast v1, La/j/t;

    invoke-interface {v1}, La/j/t;->e()La/j/s;

    move-result-object v1

    invoke-direct {v0, p0, v1}, La/k/a/b;-><init>(La/j/g;La/j/s;)V

    return-object v0
.end method


# virtual methods
.method public abstract a(Ljava/lang/String;Ljava/io/FileDescriptor;Ljava/io/PrintWriter;[Ljava/lang/String;)V
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation
.end method
