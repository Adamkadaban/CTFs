.class public La/f/j/e;
.super Ljava/lang/Object;
.source ""


# instance fields
.field public a:Landroid/view/ViewParent;

.field public b:Landroid/view/ViewParent;

.field public final c:Landroid/view/View;

.field public d:Z

.field public e:[I


# direct methods
.method public constructor <init>(Landroid/view/View;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La/f/j/e;->c:Landroid/view/View;

    return-void
.end method


# virtual methods
.method public final a(IIII[II[I)Z
    .locals 15

    move-object v0, p0

    move-object/from16 v1, p5

    .line 1
    iget-boolean v2, v0, La/f/j/e;->d:Z

    const/4 v3, 0x0

    if-eqz v2, :cond_7

    move/from16 v2, p6

    .line 2
    invoke-virtual {p0, v2}, La/f/j/e;->b(I)Landroid/view/ViewParent;

    move-result-object v4

    if-nez v4, :cond_0

    return v3

    :cond_0
    const/4 v12, 0x1

    if-nez p1, :cond_2

    if-nez p2, :cond_2

    if-nez p3, :cond_2

    if-eqz p4, :cond_1

    goto :goto_0

    :cond_1
    if-eqz v1, :cond_7

    aput v3, v1, v3

    aput v3, v1, v12

    goto :goto_3

    :cond_2
    :goto_0
    if-eqz v1, :cond_3

    iget-object v5, v0, La/f/j/e;->c:Landroid/view/View;

    invoke-virtual {v5, v1}, Landroid/view/View;->getLocationInWindow([I)V

    aget v5, v1, v3

    aget v6, v1, v12

    move v13, v5

    move v14, v6

    goto :goto_1

    :cond_3
    move v13, v3

    move v14, v13

    :goto_1
    if-nez p7, :cond_5

    .line 3
    iget-object v5, v0, La/f/j/e;->e:[I

    if-nez v5, :cond_4

    const/4 v5, 0x2

    new-array v5, v5, [I

    iput-object v5, v0, La/f/j/e;->e:[I

    :cond_4
    iget-object v5, v0, La/f/j/e;->e:[I

    .line 4
    aput v3, v5, v3

    aput v3, v5, v12

    move-object v11, v5

    goto :goto_2

    :cond_5
    move-object/from16 v11, p7

    :goto_2
    iget-object v5, v0, La/f/j/e;->c:Landroid/view/View;

    move/from16 v6, p1

    move/from16 v7, p2

    move/from16 v8, p3

    move/from16 v9, p4

    move/from16 v10, p6

    invoke-static/range {v4 .. v11}, La/b/k/h$i;->u(Landroid/view/ViewParent;Landroid/view/View;IIIII[I)V

    if-eqz v1, :cond_6

    iget-object v2, v0, La/f/j/e;->c:Landroid/view/View;

    invoke-virtual {v2, v1}, Landroid/view/View;->getLocationInWindow([I)V

    aget v2, v1, v3

    sub-int/2addr v2, v13

    aput v2, v1, v3

    aget v2, v1, v12

    sub-int/2addr v2, v14

    aput v2, v1, v12

    :cond_6
    return v12

    :cond_7
    :goto_3
    return v3
.end method

.method public final b(I)Landroid/view/ViewParent;
    .locals 1

    if-eqz p1, :cond_1

    const/4 v0, 0x1

    if-eq p1, v0, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    iget-object p1, p0, La/f/j/e;->b:Landroid/view/ViewParent;

    return-object p1

    :cond_1
    iget-object p1, p0, La/f/j/e;->a:Landroid/view/ViewParent;

    return-object p1
.end method
