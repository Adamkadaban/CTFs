.class public La/c/a/a/a;
.super La/c/a/a/c;
.source ""


# static fields
.field public static volatile c:La/c/a/a/a;


# instance fields
.field public a:La/c/a/a/c;

.field public b:La/c/a/a/c;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, La/c/a/a/c;-><init>()V

    new-instance v0, La/c/a/a/b;

    invoke-direct {v0}, La/c/a/a/b;-><init>()V

    iput-object v0, p0, La/c/a/a/a;->b:La/c/a/a/c;

    iput-object v0, p0, La/c/a/a/a;->a:La/c/a/a/c;

    return-void
.end method

.method public static b()La/c/a/a/a;
    .locals 2

    sget-object v0, La/c/a/a/a;->c:La/c/a/a/a;

    if-eqz v0, :cond_0

    sget-object v0, La/c/a/a/a;->c:La/c/a/a/a;

    return-object v0

    :cond_0
    const-class v0, La/c/a/a/a;

    monitor-enter v0

    :try_start_0
    sget-object v1, La/c/a/a/a;->c:La/c/a/a/a;

    if-nez v1, :cond_1

    new-instance v1, La/c/a/a/a;

    invoke-direct {v1}, La/c/a/a/a;-><init>()V

    sput-object v1, La/c/a/a/a;->c:La/c/a/a/a;

    :cond_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    sget-object v0, La/c/a/a/a;->c:La/c/a/a/a;

    return-object v0

    :catchall_0
    move-exception v1

    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v1
.end method


# virtual methods
.method public a()Z
    .locals 1

    iget-object v0, p0, La/c/a/a/a;->a:La/c/a/a/c;

    invoke-virtual {v0}, La/c/a/a/c;->a()Z

    move-result v0

    return v0
.end method
