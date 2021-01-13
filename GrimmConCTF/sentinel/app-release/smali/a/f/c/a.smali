.class public La/f/c/a;
.super La/f/d/a;
.source ""


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/f/c/a$a;
    }
.end annotation


# direct methods
.method public static d(Landroid/app/Activity;)V
    .locals 0

    invoke-virtual {p0}, Landroid/app/Activity;->finishAffinity()V

    return-void
.end method

.method public static e()La/f/c/a$a;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public static f(Landroid/app/Activity;)V
    .locals 2

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1c

    if-lt v0, v1, :cond_0

    :goto_0
    invoke-virtual {p0}, Landroid/app/Activity;->recreate()V

    goto :goto_1

    :cond_0
    invoke-static {p0}, La/f/c/b;->b(Landroid/app/Activity;)Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    :goto_1
    return-void
.end method
