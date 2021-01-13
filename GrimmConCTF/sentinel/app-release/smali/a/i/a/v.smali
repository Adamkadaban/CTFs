.class public La/i/a/v;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/i/a/v$a;
    }
.end annotation


# static fields
.field public static final a:[I

.field public static final b:La/i/a/d0;

.field public static final c:La/i/a/d0;


# direct methods
.method public static constructor <clinit>()V
    .locals 3

    const/16 v0, 0xb

    new-array v0, v0, [I

    fill-array-data v0, :array_0

    sput-object v0, La/i/a/v;->a:[I

    new-instance v0, La/i/a/y;

    invoke-direct {v0}, La/i/a/y;-><init>()V

    sput-object v0, La/i/a/v;->b:La/i/a/d0;

    :try_start_0
    const-string v0, "androidx.transition.FragmentTransitionSupport"

    .line 1
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v0

    const/4 v1, 0x0

    new-array v2, v1, [Ljava/lang/Class;

    invoke-virtual {v0, v2}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    move-result-object v0

    new-array v1, v1, [Ljava/lang/Object;

    invoke-virtual {v0, v1}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/i/a/d0;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    const/4 v0, 0x0

    .line 2
    :goto_0
    sput-object v0, La/i/a/v;->c:La/i/a/d0;

    return-void

    :array_0
    .array-data 4
        0x0
        0x3
        0x0
        0x1
        0x5
        0x4
        0x7
        0x6
        0x9
        0x8
        0xa
    .end array-data
.end method

.method public static a(Ljava/util/ArrayList;La/d/a;Ljava/util/Collection;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/ArrayList<",
            "Landroid/view/View;",
            ">;",
            "La/d/a<",
            "Ljava/lang/String;",
            "Landroid/view/View;",
            ">;",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    iget v0, p1, La/d/h;->d:I

    add-int/lit8 v0, v0, -0x1

    :goto_0
    if-ltz v0, :cond_1

    .line 2
    invoke-virtual {p1, v0}, La/d/h;->j(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/view/View;

    invoke-static {v1}, La/f/j/k;->i(Landroid/view/View;)Ljava/lang/String;

    move-result-object v2

    invoke-interface {p2, v2}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_0
    add-int/lit8 v0, v0, -0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public static b(La/i/a/a;La/i/a/q$a;Landroid/util/SparseArray;ZZ)V
    .locals 16
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/i/a/a;",
            "La/i/a/q$a;",
            "Landroid/util/SparseArray<",
            "La/i/a/v$a;",
            ">;ZZ)V"
        }
    .end annotation

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move/from16 v3, p3

    iget-object v10, v1, La/i/a/q$a;->b:Landroidx/fragment/app/Fragment;

    if-nez v10, :cond_0

    return-void

    :cond_0
    iget v11, v10, Landroidx/fragment/app/Fragment;->x:I

    if-nez v11, :cond_1

    return-void

    :cond_1
    if-eqz v3, :cond_2

    sget-object v4, La/i/a/v;->a:[I

    iget v1, v1, La/i/a/q$a;->a:I

    aget v1, v4, v1

    goto :goto_0

    :cond_2
    iget v1, v1, La/i/a/q$a;->a:I

    :goto_0
    const/4 v4, 0x0

    const/4 v5, 0x1

    if-eq v1, v5, :cond_a

    const/4 v6, 0x3

    if-eq v1, v6, :cond_7

    const/4 v6, 0x4

    if-eq v1, v6, :cond_5

    const/4 v6, 0x5

    if-eq v1, v6, :cond_3

    const/4 v6, 0x6

    if-eq v1, v6, :cond_7

    const/4 v6, 0x7

    if-eq v1, v6, :cond_a

    move v1, v4

    move v12, v1

    move v13, v12

    goto/16 :goto_5

    :cond_3
    if-eqz p4, :cond_4

    iget-boolean v1, v10, Landroidx/fragment/app/Fragment;->M:Z

    if-eqz v1, :cond_c

    iget-boolean v1, v10, Landroidx/fragment/app/Fragment;->z:Z

    if-nez v1, :cond_c

    iget-boolean v1, v10, Landroidx/fragment/app/Fragment;->l:Z

    if-eqz v1, :cond_c

    goto :goto_3

    :cond_4
    iget-boolean v1, v10, Landroidx/fragment/app/Fragment;->z:Z

    goto :goto_4

    :cond_5
    if-eqz p4, :cond_6

    iget-boolean v1, v10, Landroidx/fragment/app/Fragment;->M:Z

    if-eqz v1, :cond_9

    iget-boolean v1, v10, Landroidx/fragment/app/Fragment;->l:Z

    if-eqz v1, :cond_9

    iget-boolean v1, v10, Landroidx/fragment/app/Fragment;->z:Z

    if-eqz v1, :cond_9

    goto :goto_1

    :cond_6
    iget-boolean v1, v10, Landroidx/fragment/app/Fragment;->l:Z

    if-eqz v1, :cond_9

    iget-boolean v1, v10, Landroidx/fragment/app/Fragment;->z:Z

    if-nez v1, :cond_9

    goto :goto_1

    :cond_7
    iget-boolean v1, v10, Landroidx/fragment/app/Fragment;->l:Z

    if-eqz p4, :cond_8

    if-nez v1, :cond_9

    iget-object v1, v10, Landroidx/fragment/app/Fragment;->G:Landroid/view/View;

    if-eqz v1, :cond_9

    invoke-virtual {v1}, Landroid/view/View;->getVisibility()I

    move-result v1

    if-nez v1, :cond_9

    iget v1, v10, Landroidx/fragment/app/Fragment;->N:F

    const/4 v6, 0x0

    cmpl-float v1, v1, v6

    if-ltz v1, :cond_9

    goto :goto_1

    :cond_8
    if-eqz v1, :cond_9

    iget-boolean v1, v10, Landroidx/fragment/app/Fragment;->z:Z

    if-nez v1, :cond_9

    :goto_1
    move v1, v5

    goto :goto_2

    :cond_9
    move v1, v4

    :goto_2
    move v13, v1

    move v1, v4

    move v12, v5

    goto :goto_5

    :cond_a
    if-eqz p4, :cond_b

    iget-boolean v1, v10, Landroidx/fragment/app/Fragment;->L:Z

    goto :goto_4

    :cond_b
    iget-boolean v1, v10, Landroidx/fragment/app/Fragment;->l:Z

    if-nez v1, :cond_c

    iget-boolean v1, v10, Landroidx/fragment/app/Fragment;->z:Z

    if-nez v1, :cond_c

    :goto_3
    move v1, v5

    goto :goto_4

    :cond_c
    move v1, v4

    :goto_4
    move v12, v4

    move v13, v12

    move v4, v1

    move v1, v5

    :goto_5
    invoke-virtual {v2, v11}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, La/i/a/v$a;

    if-eqz v4, :cond_e

    if-nez v6, :cond_d

    .line 1
    new-instance v4, La/i/a/v$a;

    invoke-direct {v4}, La/i/a/v$a;-><init>()V

    invoke-virtual {v2, v11, v4}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    move-object v6, v4

    .line 2
    :cond_d
    iput-object v10, v6, La/i/a/v$a;->a:Landroidx/fragment/app/Fragment;

    iput-boolean v3, v6, La/i/a/v$a;->b:Z

    iput-object v0, v6, La/i/a/v$a;->c:La/i/a/a;

    :cond_e
    move-object v14, v6

    const/4 v15, 0x0

    if-nez p4, :cond_10

    if-eqz v1, :cond_10

    if-eqz v14, :cond_f

    iget-object v1, v14, La/i/a/v$a;->d:Landroidx/fragment/app/Fragment;

    if-ne v1, v10, :cond_f

    iput-object v15, v14, La/i/a/v$a;->d:Landroidx/fragment/app/Fragment;

    :cond_f
    iget-object v4, v0, La/i/a/a;->r:La/i/a/j;

    iget v1, v10, Landroidx/fragment/app/Fragment;->b:I

    if-ge v1, v5, :cond_10

    iget v1, v4, La/i/a/j;->o:I

    if-lt v1, v5, :cond_10

    iget-boolean v1, v0, La/i/a/q;->p:Z

    if-nez v1, :cond_10

    invoke-virtual {v4, v10}, La/i/a/j;->V(Landroidx/fragment/app/Fragment;)V

    const/4 v6, 0x1

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    move-object v5, v10

    invoke-virtual/range {v4 .. v9}, La/i/a/j;->Z(Landroidx/fragment/app/Fragment;IIIZ)V

    :cond_10
    if-eqz v13, :cond_13

    if-eqz v14, :cond_11

    iget-object v1, v14, La/i/a/v$a;->d:Landroidx/fragment/app/Fragment;

    if-nez v1, :cond_13

    :cond_11
    if-nez v14, :cond_12

    .line 3
    new-instance v1, La/i/a/v$a;

    invoke-direct {v1}, La/i/a/v$a;-><init>()V

    invoke-virtual {v2, v11, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    move-object v14, v1

    .line 4
    :cond_12
    iput-object v10, v14, La/i/a/v$a;->d:Landroidx/fragment/app/Fragment;

    iput-boolean v3, v14, La/i/a/v$a;->e:Z

    iput-object v0, v14, La/i/a/v$a;->f:La/i/a/a;

    :cond_13
    if-nez p4, :cond_14

    if-eqz v12, :cond_14

    if-eqz v14, :cond_14

    iget-object v0, v14, La/i/a/v$a;->a:Landroidx/fragment/app/Fragment;

    if-ne v0, v10, :cond_14

    iput-object v15, v14, La/i/a/v$a;->a:Landroidx/fragment/app/Fragment;

    :cond_14
    return-void
.end method

.method public static c(Landroidx/fragment/app/Fragment;Landroidx/fragment/app/Fragment;ZLa/d/a;Z)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroidx/fragment/app/Fragment;",
            "Landroidx/fragment/app/Fragment;",
            "Z",
            "La/d/a<",
            "Ljava/lang/String;",
            "Landroid/view/View;",
            ">;Z)V"
        }
    .end annotation

    if-eqz p2, :cond_0

    .line 1
    iget-object p0, p1, Landroidx/fragment/app/Fragment;->K:Landroidx/fragment/app/Fragment$b;

    goto :goto_0

    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/Fragment;->K:Landroidx/fragment/app/Fragment$b;

    :goto_0
    return-void
.end method

.method public static d(La/i/a/d0;Ljava/util/List;)Z
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/i/a/d0;",
            "Ljava/util/List<",
            "Ljava/lang/Object;",
            ">;)Z"
        }
    .end annotation

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v0

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    if-ge v2, v0, :cond_2

    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    move-object v4, p0

    check-cast v4, La/i/a/y;

    if-eqz v4, :cond_1

    .line 1
    instance-of v3, v3, Landroid/transition/Transition;

    if-nez v3, :cond_0

    return v1

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    const/4 p0, 0x0

    throw p0

    :cond_2
    const/4 p0, 0x1

    return p0
.end method

.method public static e(La/i/a/d0;La/d/a;Ljava/lang/Object;La/i/a/v$a;)La/d/a;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/i/a/d0;",
            "La/d/a<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/Object;",
            "La/i/a/v$a;",
            ")",
            "La/d/a<",
            "Ljava/lang/String;",
            "Landroid/view/View;",
            ">;"
        }
    .end annotation

    iget-object v0, p3, La/i/a/v$a;->a:Landroidx/fragment/app/Fragment;

    .line 1
    iget-object v0, v0, Landroidx/fragment/app/Fragment;->G:Landroid/view/View;

    .line 2
    invoke-virtual {p1}, La/d/h;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_5

    if-eqz p2, :cond_5

    if-nez v0, :cond_0

    goto :goto_2

    :cond_0
    new-instance p2, La/d/a;

    invoke-direct {p2}, La/d/a;-><init>()V

    invoke-virtual {p0, p2, v0}, La/i/a/d0;->e(Ljava/util/Map;Landroid/view/View;)V

    iget-object p0, p3, La/i/a/v$a;->c:La/i/a/a;

    iget-boolean p3, p3, La/i/a/v$a;->b:Z

    if-eqz p3, :cond_1

    iget-object p0, p0, La/i/a/q;->n:Ljava/util/ArrayList;

    goto :goto_0

    :cond_1
    iget-object p0, p0, La/i/a/q;->o:Ljava/util/ArrayList;

    :goto_0
    if-eqz p0, :cond_2

    .line 3
    invoke-static {p2, p0}, La/d/g;->k(Ljava/util/Map;Ljava/util/Collection;)Z

    .line 4
    invoke-virtual {p1}, La/d/a;->values()Ljava/util/Collection;

    move-result-object p0

    .line 5
    invoke-static {p2, p0}, La/d/g;->k(Ljava/util/Map;Ljava/util/Collection;)Z

    .line 6
    :cond_2
    iget p0, p1, La/d/h;->d:I

    :cond_3
    :goto_1
    add-int/lit8 p0, p0, -0x1

    if-ltz p0, :cond_4

    .line 7
    invoke-virtual {p1, p0}, La/d/h;->j(I)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Ljava/lang/String;

    invoke-virtual {p2, p3}, La/d/h;->containsKey(Ljava/lang/Object;)Z

    move-result p3

    if-nez p3, :cond_3

    invoke-virtual {p1, p0}, La/d/h;->h(I)Ljava/lang/Object;

    goto :goto_1

    :cond_4
    return-object p2

    .line 8
    :cond_5
    :goto_2
    invoke-virtual {p1}, La/d/h;->clear()V

    const/4 p0, 0x0

    return-object p0
.end method

.method public static f(La/i/a/d0;La/d/a;Ljava/lang/Object;La/i/a/v$a;)La/d/a;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/i/a/d0;",
            "La/d/a<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/Object;",
            "La/i/a/v$a;",
            ")",
            "La/d/a<",
            "Ljava/lang/String;",
            "Landroid/view/View;",
            ">;"
        }
    .end annotation

    invoke-virtual {p1}, La/d/h;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_2

    if-nez p2, :cond_0

    goto :goto_1

    :cond_0
    iget-object p2, p3, La/i/a/v$a;->d:Landroidx/fragment/app/Fragment;

    new-instance v0, La/d/a;

    invoke-direct {v0}, La/d/a;-><init>()V

    invoke-virtual {p2}, Landroidx/fragment/app/Fragment;->B()Landroid/view/View;

    move-result-object p2

    invoke-virtual {p0, v0, p2}, La/i/a/d0;->e(Ljava/util/Map;Landroid/view/View;)V

    iget-object p0, p3, La/i/a/v$a;->f:La/i/a/a;

    iget-boolean p2, p3, La/i/a/v$a;->e:Z

    if-eqz p2, :cond_1

    iget-object p0, p0, La/i/a/q;->o:Ljava/util/ArrayList;

    goto :goto_0

    :cond_1
    iget-object p0, p0, La/i/a/q;->n:Ljava/util/ArrayList;

    .line 1
    :goto_0
    invoke-static {v0, p0}, La/d/g;->k(Ljava/util/Map;Ljava/util/Collection;)Z

    .line 2
    invoke-virtual {v0}, La/d/a;->keySet()Ljava/util/Set;

    move-result-object p0

    .line 3
    invoke-static {p1, p0}, La/d/g;->k(Ljava/util/Map;Ljava/util/Collection;)Z

    return-object v0

    .line 4
    :cond_2
    :goto_1
    invoke-virtual {p1}, La/d/h;->clear()V

    const/4 p0, 0x0

    return-object p0
.end method

.method public static g(Landroidx/fragment/app/Fragment;Landroidx/fragment/app/Fragment;)La/i/a/d0;
    .locals 4

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    const/4 v1, 0x0

    if-eqz p0, :cond_6

    invoke-virtual {p0}, Landroidx/fragment/app/Fragment;->l()Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_0

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1
    :cond_0
    iget-object v2, p0, Landroidx/fragment/app/Fragment;->K:Landroidx/fragment/app/Fragment$b;

    if-nez v2, :cond_1

    move-object v2, v1

    goto :goto_0

    :cond_1
    iget-object v2, v2, Landroidx/fragment/app/Fragment$b;->h:Ljava/lang/Object;

    sget-object v3, Landroidx/fragment/app/Fragment;->V:Ljava/lang/Object;

    if-ne v2, v3, :cond_2

    invoke-virtual {p0}, Landroidx/fragment/app/Fragment;->k()Ljava/lang/Object;

    move-result-object v2

    :cond_2
    :goto_0
    if-eqz v2, :cond_3

    .line 2
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 3
    :cond_3
    iget-object v2, p0, Landroidx/fragment/app/Fragment;->K:Landroidx/fragment/app/Fragment$b;

    if-nez v2, :cond_4

    move-object v2, v1

    goto :goto_1

    :cond_4
    iget-object v2, v2, Landroidx/fragment/app/Fragment$b;->l:Ljava/lang/Object;

    sget-object v3, Landroidx/fragment/app/Fragment;->V:Ljava/lang/Object;

    if-ne v2, v3, :cond_5

    invoke-virtual {p0}, Landroidx/fragment/app/Fragment;->p()Ljava/lang/Object;

    move-result-object v2

    :cond_5
    :goto_1
    if-eqz v2, :cond_6

    .line 4
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_6
    if-eqz p1, :cond_b

    invoke-virtual {p1}, Landroidx/fragment/app/Fragment;->k()Ljava/lang/Object;

    move-result-object p0

    if-eqz p0, :cond_7

    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 5
    :cond_7
    iget-object p0, p1, Landroidx/fragment/app/Fragment;->K:Landroidx/fragment/app/Fragment$b;

    if-nez p0, :cond_8

    move-object p0, v1

    goto :goto_2

    :cond_8
    iget-object p0, p0, Landroidx/fragment/app/Fragment$b;->j:Ljava/lang/Object;

    sget-object v2, Landroidx/fragment/app/Fragment;->V:Ljava/lang/Object;

    if-ne p0, v2, :cond_9

    invoke-virtual {p1}, Landroidx/fragment/app/Fragment;->l()Ljava/lang/Object;

    move-result-object p0

    :cond_9
    :goto_2
    if-eqz p0, :cond_a

    .line 6
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_a
    invoke-virtual {p1}, Landroidx/fragment/app/Fragment;->p()Ljava/lang/Object;

    move-result-object p0

    if-eqz p0, :cond_b

    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_b
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p0

    if-eqz p0, :cond_c

    return-object v1

    :cond_c
    sget-object p0, La/i/a/v;->b:La/i/a/d0;

    invoke-static {p0, v0}, La/i/a/v;->d(La/i/a/d0;Ljava/util/List;)Z

    move-result p0

    if-eqz p0, :cond_d

    sget-object p0, La/i/a/v;->b:La/i/a/d0;

    return-object p0

    :cond_d
    sget-object p0, La/i/a/v;->c:La/i/a/d0;

    if-eqz p0, :cond_e

    invoke-static {p0, v0}, La/i/a/v;->d(La/i/a/d0;Ljava/util/List;)Z

    move-result p0

    if-eqz p0, :cond_e

    sget-object p0, La/i/a/v;->c:La/i/a/d0;

    return-object p0

    :cond_e
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Invalid Transition types"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static h(La/i/a/d0;Ljava/lang/Object;Landroidx/fragment/app/Fragment;Ljava/util/ArrayList;Landroid/view/View;)Ljava/util/ArrayList;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/i/a/d0;",
            "Ljava/lang/Object;",
            "Landroidx/fragment/app/Fragment;",
            "Ljava/util/ArrayList<",
            "Landroid/view/View;",
            ">;",
            "Landroid/view/View;",
            ")",
            "Ljava/util/ArrayList<",
            "Landroid/view/View;",
            ">;"
        }
    .end annotation

    if-eqz p1, :cond_2

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 1
    iget-object p2, p2, Landroidx/fragment/app/Fragment;->G:Landroid/view/View;

    if-eqz p2, :cond_0

    .line 2
    invoke-virtual {p0, v0, p2}, La/i/a/d0;->b(Ljava/util/ArrayList;Landroid/view/View;)V

    :cond_0
    if-eqz p3, :cond_1

    invoke-virtual {v0, p3}, Ljava/util/ArrayList;->removeAll(Ljava/util/Collection;)Z

    :cond_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p2

    if-nez p2, :cond_3

    invoke-virtual {v0, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {p0, p1, v0}, La/i/a/d0;->a(Ljava/lang/Object;Ljava/util/ArrayList;)V

    goto :goto_0

    :cond_2
    const/4 v0, 0x0

    :cond_3
    :goto_0
    return-object v0
.end method

.method public static i(La/i/a/d0;Landroidx/fragment/app/Fragment;Z)Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    if-eqz p2, :cond_2

    .line 1
    iget-object p2, p1, Landroidx/fragment/app/Fragment;->K:Landroidx/fragment/app/Fragment$b;

    if-nez p2, :cond_1

    goto :goto_0

    :cond_1
    iget-object v0, p2, Landroidx/fragment/app/Fragment$b;->j:Ljava/lang/Object;

    sget-object p2, Landroidx/fragment/app/Fragment;->V:Ljava/lang/Object;

    if-ne v0, p2, :cond_3

    invoke-virtual {p1}, Landroidx/fragment/app/Fragment;->l()Ljava/lang/Object;

    move-result-object v0

    goto :goto_0

    .line 2
    :cond_2
    invoke-virtual {p1}, Landroidx/fragment/app/Fragment;->k()Ljava/lang/Object;

    move-result-object v0

    :cond_3
    :goto_0
    invoke-virtual {p0, v0}, La/i/a/d0;->c(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public static j(La/i/a/d0;Landroidx/fragment/app/Fragment;Z)Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    if-eqz p2, :cond_2

    .line 1
    iget-object p2, p1, Landroidx/fragment/app/Fragment;->K:Landroidx/fragment/app/Fragment$b;

    if-nez p2, :cond_1

    goto :goto_0

    :cond_1
    iget-object v0, p2, Landroidx/fragment/app/Fragment$b;->h:Ljava/lang/Object;

    sget-object p2, Landroidx/fragment/app/Fragment;->V:Ljava/lang/Object;

    if-ne v0, p2, :cond_3

    invoke-virtual {p1}, Landroidx/fragment/app/Fragment;->k()Ljava/lang/Object;

    move-result-object v0

    goto :goto_0

    .line 2
    :cond_2
    invoke-virtual {p1}, Landroidx/fragment/app/Fragment;->l()Ljava/lang/Object;

    move-result-object v0

    :cond_3
    :goto_0
    invoke-virtual {p0, v0}, La/i/a/d0;->c(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public static k(La/d/a;La/i/a/v$a;Ljava/lang/Object;Z)Landroid/view/View;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/d/a<",
            "Ljava/lang/String;",
            "Landroid/view/View;",
            ">;",
            "La/i/a/v$a;",
            "Ljava/lang/Object;",
            "Z)",
            "Landroid/view/View;"
        }
    .end annotation

    iget-object p1, p1, La/i/a/v$a;->c:La/i/a/a;

    if-eqz p2, :cond_1

    if-eqz p0, :cond_1

    iget-object p2, p1, La/i/a/q;->n:Ljava/util/ArrayList;

    if-eqz p2, :cond_1

    invoke-virtual {p2}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p2

    if-nez p2, :cond_1

    const/4 p2, 0x0

    if-eqz p3, :cond_0

    iget-object p1, p1, La/i/a/q;->n:Ljava/util/ArrayList;

    goto :goto_0

    :cond_0
    iget-object p1, p1, La/i/a/q;->o:Ljava/util/ArrayList;

    :goto_0
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/String;

    invoke-virtual {p0, p1}, La/d/h;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Landroid/view/View;

    return-object p0

    :cond_1
    const/4 p0, 0x0

    return-object p0
.end method

.method public static l(La/i/a/d0;Landroidx/fragment/app/Fragment;Landroidx/fragment/app/Fragment;Z)Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    if-eqz p3, :cond_1

    .line 1
    iget-object p1, p2, Landroidx/fragment/app/Fragment;->K:Landroidx/fragment/app/Fragment$b;

    if-nez p1, :cond_0

    move-object p1, v0

    goto :goto_0

    :cond_0
    iget-object p1, p1, Landroidx/fragment/app/Fragment$b;->l:Ljava/lang/Object;

    sget-object p3, Landroidx/fragment/app/Fragment;->V:Ljava/lang/Object;

    if-ne p1, p3, :cond_2

    invoke-virtual {p2}, Landroidx/fragment/app/Fragment;->p()Ljava/lang/Object;

    move-result-object p1

    goto :goto_0

    .line 2
    :cond_1
    invoke-virtual {p1}, Landroidx/fragment/app/Fragment;->p()Ljava/lang/Object;

    move-result-object p1

    :cond_2
    :goto_0
    invoke-virtual {p0, p1}, La/i/a/d0;->c(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    if-nez p0, :cond_3

    goto :goto_1

    .line 3
    :cond_3
    new-instance v0, Landroid/transition/TransitionSet;

    invoke-direct {v0}, Landroid/transition/TransitionSet;-><init>()V

    check-cast p0, Landroid/transition/Transition;

    invoke-virtual {v0, p0}, Landroid/transition/TransitionSet;->addTransition(Landroid/transition/Transition;)Landroid/transition/TransitionSet;

    :goto_1
    return-object v0
.end method

.method public static m(La/i/a/d0;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Landroidx/fragment/app/Fragment;Z)Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x1

    if-eqz p1, :cond_3

    if-eqz p2, :cond_3

    if-eqz p4, :cond_3

    if-eqz p5, :cond_1

    .line 1
    iget-object p4, p4, Landroidx/fragment/app/Fragment;->K:Landroidx/fragment/app/Fragment$b;

    if-eqz p4, :cond_3

    iget-object p4, p4, Landroidx/fragment/app/Fragment$b;->m:Ljava/lang/Boolean;

    if-nez p4, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p4

    goto :goto_1

    .line 2
    :cond_1
    iget-object p4, p4, Landroidx/fragment/app/Fragment;->K:Landroidx/fragment/app/Fragment$b;

    if-eqz p4, :cond_3

    iget-object p4, p4, Landroidx/fragment/app/Fragment$b;->n:Ljava/lang/Boolean;

    if-nez p4, :cond_2

    goto :goto_0

    :cond_2
    invoke-virtual {p4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p4

    goto :goto_1

    :cond_3
    :goto_0
    move p4, v0

    :goto_1
    const/4 p5, 0x0

    .line 3
    check-cast p0, La/i/a/y;

    if-eqz p4, :cond_6

    .line 4
    new-instance p0, Landroid/transition/TransitionSet;

    invoke-direct {p0}, Landroid/transition/TransitionSet;-><init>()V

    if-eqz p2, :cond_4

    check-cast p2, Landroid/transition/Transition;

    invoke-virtual {p0, p2}, Landroid/transition/TransitionSet;->addTransition(Landroid/transition/Transition;)Landroid/transition/TransitionSet;

    :cond_4
    if-eqz p1, :cond_5

    check-cast p1, Landroid/transition/Transition;

    invoke-virtual {p0, p1}, Landroid/transition/TransitionSet;->addTransition(Landroid/transition/Transition;)Landroid/transition/TransitionSet;

    :cond_5
    if-eqz p3, :cond_c

    check-cast p3, Landroid/transition/Transition;

    invoke-virtual {p0, p3}, Landroid/transition/TransitionSet;->addTransition(Landroid/transition/Transition;)Landroid/transition/TransitionSet;

    goto :goto_3

    .line 5
    :cond_6
    check-cast p2, Landroid/transition/Transition;

    check-cast p1, Landroid/transition/Transition;

    check-cast p3, Landroid/transition/Transition;

    if-eqz p2, :cond_7

    if-eqz p1, :cond_7

    new-instance p0, Landroid/transition/TransitionSet;

    invoke-direct {p0}, Landroid/transition/TransitionSet;-><init>()V

    invoke-virtual {p0, p2}, Landroid/transition/TransitionSet;->addTransition(Landroid/transition/Transition;)Landroid/transition/TransitionSet;

    move-result-object p0

    invoke-virtual {p0, p1}, Landroid/transition/TransitionSet;->addTransition(Landroid/transition/Transition;)Landroid/transition/TransitionSet;

    move-result-object p0

    invoke-virtual {p0, v0}, Landroid/transition/TransitionSet;->setOrdering(I)Landroid/transition/TransitionSet;

    move-result-object p5

    goto :goto_2

    :cond_7
    if-eqz p2, :cond_8

    move-object p5, p2

    goto :goto_2

    :cond_8
    if-eqz p1, :cond_9

    move-object p5, p1

    :cond_9
    :goto_2
    if-eqz p3, :cond_b

    new-instance p0, Landroid/transition/TransitionSet;

    invoke-direct {p0}, Landroid/transition/TransitionSet;-><init>()V

    if-eqz p5, :cond_a

    invoke-virtual {p0, p5}, Landroid/transition/TransitionSet;->addTransition(Landroid/transition/Transition;)Landroid/transition/TransitionSet;

    :cond_a
    invoke-virtual {p0, p3}, Landroid/transition/TransitionSet;->addTransition(Landroid/transition/Transition;)Landroid/transition/TransitionSet;

    goto :goto_3

    :cond_b
    move-object p0, p5

    :cond_c
    :goto_3
    return-object p0
.end method

.method public static n(La/i/a/d0;Ljava/lang/Object;Ljava/lang/Object;La/d/a;ZLa/i/a/a;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/i/a/d0;",
            "Ljava/lang/Object;",
            "Ljava/lang/Object;",
            "La/d/a<",
            "Ljava/lang/String;",
            "Landroid/view/View;",
            ">;Z",
            "La/i/a/a;",
            ")V"
        }
    .end annotation

    iget-object v0, p5, La/i/a/q;->n:Ljava/util/ArrayList;

    if-eqz v0, :cond_2

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_2

    const/4 v0, 0x0

    if-eqz p4, :cond_0

    iget-object p4, p5, La/i/a/q;->o:Ljava/util/ArrayList;

    goto :goto_0

    :cond_0
    iget-object p4, p5, La/i/a/q;->n:Ljava/util/ArrayList;

    :goto_0
    invoke-virtual {p4, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p4

    check-cast p4, Ljava/lang/String;

    invoke-virtual {p3, p4}, La/d/h;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Landroid/view/View;

    check-cast p0, La/i/a/y;

    if-eqz p3, :cond_1

    .line 1
    check-cast p1, Landroid/transition/Transition;

    new-instance p4, Landroid/graphics/Rect;

    invoke-direct {p4}, Landroid/graphics/Rect;-><init>()V

    invoke-virtual {p0, p3, p4}, La/i/a/d0;->f(Landroid/view/View;Landroid/graphics/Rect;)V

    new-instance p5, La/i/a/w;

    invoke-direct {p5, p0, p4}, La/i/a/w;-><init>(La/i/a/y;Landroid/graphics/Rect;)V

    invoke-virtual {p1, p5}, Landroid/transition/Transition;->setEpicenterCallback(Landroid/transition/Transition$EpicenterCallback;)V

    :cond_1
    if-eqz p2, :cond_2

    if-eqz p3, :cond_2

    check-cast p2, Landroid/transition/Transition;

    new-instance p1, Landroid/graphics/Rect;

    invoke-direct {p1}, Landroid/graphics/Rect;-><init>()V

    invoke-virtual {p0, p3, p1}, La/i/a/d0;->f(Landroid/view/View;Landroid/graphics/Rect;)V

    new-instance p3, La/i/a/w;

    invoke-direct {p3, p0, p1}, La/i/a/w;-><init>(La/i/a/y;Landroid/graphics/Rect;)V

    invoke-virtual {p2, p3}, Landroid/transition/Transition;->setEpicenterCallback(Landroid/transition/Transition$EpicenterCallback;)V

    :cond_2
    return-void
.end method

.method public static o(Ljava/util/ArrayList;I)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/ArrayList<",
            "Landroid/view/View;",
            ">;I)V"
        }
    .end annotation

    if-nez p0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    move-result v0

    add-int/lit8 v0, v0, -0x1

    :goto_0
    if-ltz v0, :cond_1

    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/view/View;

    invoke-virtual {v1, p1}, Landroid/view/View;->setVisibility(I)V

    add-int/lit8 v0, v0, -0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public static p(La/i/a/j;Ljava/util/ArrayList;Ljava/util/ArrayList;IIZ)V
    .locals 39
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/i/a/j;",
            "Ljava/util/ArrayList<",
            "La/i/a/a;",
            ">;",
            "Ljava/util/ArrayList<",
            "Ljava/lang/Boolean;",
            ">;IIZ)V"
        }
    .end annotation

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move/from16 v3, p4

    move/from16 v4, p5

    iget v5, v0, La/i/a/j;->o:I

    const/4 v6, 0x1

    if-ge v5, v6, :cond_0

    return-void

    :cond_0
    new-instance v5, Landroid/util/SparseArray;

    invoke-direct {v5}, Landroid/util/SparseArray;-><init>()V

    move/from16 v7, p3

    :goto_0
    const/4 v8, 0x0

    if-ge v7, v3, :cond_4

    invoke-virtual {v1, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, La/i/a/a;

    invoke-virtual {v2, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/lang/Boolean;

    invoke-virtual {v10}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v10

    if-eqz v10, :cond_2

    .line 1
    iget-object v8, v9, La/i/a/a;->r:La/i/a/j;

    iget-object v8, v8, La/i/a/j;->q:La/i/a/e;

    invoke-virtual {v8}, La/i/a/e;->f()Z

    move-result v8

    if-nez v8, :cond_1

    goto :goto_3

    :cond_1
    iget-object v8, v9, La/i/a/q;->a:Ljava/util/ArrayList;

    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    move-result v8

    sub-int/2addr v8, v6

    :goto_1
    if-ltz v8, :cond_3

    iget-object v10, v9, La/i/a/q;->a:Ljava/util/ArrayList;

    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, La/i/a/q$a;

    invoke-static {v9, v10, v5, v6, v4}, La/i/a/v;->b(La/i/a/a;La/i/a/q$a;Landroid/util/SparseArray;ZZ)V

    add-int/lit8 v8, v8, -0x1

    goto :goto_1

    .line 2
    :cond_2
    iget-object v10, v9, La/i/a/q;->a:Ljava/util/ArrayList;

    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    move-result v10

    move v11, v8

    :goto_2
    if-ge v11, v10, :cond_3

    iget-object v12, v9, La/i/a/q;->a:Ljava/util/ArrayList;

    invoke-virtual {v12, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, La/i/a/q$a;

    invoke-static {v9, v12, v5, v8, v4}, La/i/a/v;->b(La/i/a/a;La/i/a/q$a;Landroid/util/SparseArray;ZZ)V

    add-int/lit8 v11, v11, 0x1

    goto :goto_2

    :cond_3
    :goto_3
    add-int/lit8 v7, v7, 0x1

    goto :goto_0

    .line 3
    :cond_4
    invoke-virtual {v5}, Landroid/util/SparseArray;->size()I

    move-result v7

    if-eqz v7, :cond_30

    new-instance v7, Landroid/view/View;

    iget-object v9, v0, La/i/a/j;->p:La/i/a/h;

    .line 4
    iget-object v9, v9, La/i/a/h;->c:Landroid/content/Context;

    .line 5
    invoke-direct {v7, v9}, Landroid/view/View;-><init>(Landroid/content/Context;)V

    invoke-virtual {v5}, Landroid/util/SparseArray;->size()I

    move-result v15

    move v14, v8

    :goto_4
    if-ge v14, v15, :cond_30

    invoke-virtual {v5, v14}, Landroid/util/SparseArray;->keyAt(I)I

    move-result v9

    .line 6
    new-instance v13, La/d/a;

    invoke-direct {v13}, La/d/a;-><init>()V

    add-int/lit8 v10, v3, -0x1

    move/from16 v12, p3

    :goto_5
    if-lt v10, v12, :cond_9

    invoke-virtual {v1, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, La/i/a/a;

    invoke-virtual {v11, v9}, La/i/a/a;->e(I)Z

    move-result v16

    if-nez v16, :cond_5

    goto :goto_9

    :cond_5
    invoke-virtual {v2, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v16

    check-cast v16, Ljava/lang/Boolean;

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v16

    iget-object v6, v11, La/i/a/q;->n:Ljava/util/ArrayList;

    if-eqz v6, :cond_8

    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    move-result v6

    iget-object v8, v11, La/i/a/q;->n:Ljava/util/ArrayList;

    iget-object v11, v11, La/i/a/q;->o:Ljava/util/ArrayList;

    if-eqz v16, :cond_6

    goto :goto_6

    :cond_6
    move-object/from16 v38, v11

    move-object v11, v8

    move-object/from16 v8, v38

    :goto_6
    const/4 v1, 0x0

    :goto_7
    if-ge v1, v6, :cond_8

    invoke-virtual {v11, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v16

    move-object/from16 v2, v16

    check-cast v2, Ljava/lang/String;

    invoke-virtual {v8, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v16

    move-object/from16 v3, v16

    check-cast v3, Ljava/lang/String;

    invoke-virtual {v13, v3}, La/d/h;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v16

    move/from16 v17, v6

    move-object/from16 v6, v16

    check-cast v6, Ljava/lang/String;

    if-eqz v6, :cond_7

    invoke-virtual {v13, v2, v6}, La/d/h;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_8

    :cond_7
    invoke-virtual {v13, v2, v3}, La/d/h;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :goto_8
    add-int/lit8 v1, v1, 0x1

    move-object/from16 v2, p2

    move/from16 v3, p4

    move/from16 v6, v17

    goto :goto_7

    :cond_8
    :goto_9
    add-int/lit8 v10, v10, -0x1

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move/from16 v3, p4

    const/4 v6, 0x1

    const/4 v8, 0x0

    goto :goto_5

    .line 7
    :cond_9
    invoke-virtual {v5, v14}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/i/a/v$a;

    if-eqz v4, :cond_20

    .line 8
    iget-object v3, v0, La/i/a/j;->q:La/i/a/e;

    invoke-virtual {v3}, La/i/a/e;->f()Z

    move-result v3

    if-eqz v3, :cond_a

    iget-object v3, v0, La/i/a/j;->q:La/i/a/e;

    invoke-virtual {v3, v9}, La/i/a/e;->b(I)Landroid/view/View;

    move-result-object v3

    check-cast v3, Landroid/view/ViewGroup;

    goto :goto_a

    :cond_a
    const/4 v3, 0x0

    :goto_a
    if-nez v3, :cond_b

    goto :goto_b

    :cond_b
    iget-object v6, v1, La/i/a/v$a;->a:Landroidx/fragment/app/Fragment;

    iget-object v8, v1, La/i/a/v$a;->d:Landroidx/fragment/app/Fragment;

    invoke-static {v8, v6}, La/i/a/v;->g(Landroidx/fragment/app/Fragment;Landroidx/fragment/app/Fragment;)La/i/a/d0;

    move-result-object v9

    if-nez v9, :cond_d

    :goto_b
    move-object/from16 v31, v5

    move/from16 v32, v14

    move/from16 v33, v15

    :cond_c
    :goto_c
    const/4 v0, 0x0

    goto/16 :goto_19

    :cond_d
    iget-boolean v10, v1, La/i/a/v$a;->b:Z

    iget-boolean v11, v1, La/i/a/v$a;->e:Z

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    move-object/from16 v31, v5

    invoke-static {v9, v6, v10}, La/i/a/v;->i(La/i/a/d0;Landroidx/fragment/app/Fragment;Z)Ljava/lang/Object;

    move-result-object v5

    invoke-static {v9, v8, v11}, La/i/a/v;->j(La/i/a/d0;Landroidx/fragment/app/Fragment;Z)Ljava/lang/Object;

    move-result-object v11

    .line 9
    iget-object v12, v1, La/i/a/v$a;->a:Landroidx/fragment/app/Fragment;

    move/from16 v32, v14

    iget-object v14, v1, La/i/a/v$a;->d:Landroidx/fragment/app/Fragment;

    move/from16 v33, v15

    if-eqz v12, :cond_e

    invoke-virtual {v12}, Landroidx/fragment/app/Fragment;->B()Landroid/view/View;

    move-result-object v15

    const/4 v0, 0x0

    invoke-virtual {v15, v0}, Landroid/view/View;->setVisibility(I)V

    :cond_e
    if-eqz v12, :cond_17

    if-nez v14, :cond_f

    goto/16 :goto_12

    :cond_f
    iget-boolean v0, v1, La/i/a/v$a;->b:Z

    invoke-virtual {v13}, La/d/h;->isEmpty()Z

    move-result v15

    if-eqz v15, :cond_10

    move/from16 v34, v10

    const/4 v15, 0x0

    goto :goto_d

    :cond_10
    invoke-static {v9, v12, v14, v0}, La/i/a/v;->l(La/i/a/d0;Landroidx/fragment/app/Fragment;Landroidx/fragment/app/Fragment;Z)Ljava/lang/Object;

    move-result-object v15

    move/from16 v34, v10

    :goto_d
    invoke-static {v9, v13, v15, v1}, La/i/a/v;->f(La/i/a/d0;La/d/a;Ljava/lang/Object;La/i/a/v$a;)La/d/a;

    move-result-object v10

    move-object/from16 v35, v6

    invoke-static {v9, v13, v15, v1}, La/i/a/v;->e(La/i/a/d0;La/d/a;Ljava/lang/Object;La/i/a/v$a;)La/d/a;

    move-result-object v6

    invoke-virtual {v13}, La/d/h;->isEmpty()Z

    move-result v16

    if-eqz v16, :cond_13

    if-eqz v10, :cond_11

    invoke-virtual {v10}, La/d/h;->clear()V

    :cond_11
    if-eqz v6, :cond_12

    invoke-virtual {v6}, La/d/h;->clear()V

    :cond_12
    const/4 v15, 0x0

    goto :goto_e

    :cond_13
    move-object/from16 v16, v15

    invoke-virtual {v13}, La/d/a;->keySet()Ljava/util/Set;

    move-result-object v15

    invoke-static {v4, v10, v15}, La/i/a/v;->a(Ljava/util/ArrayList;La/d/a;Ljava/util/Collection;)V

    invoke-virtual {v13}, La/d/a;->values()Ljava/util/Collection;

    move-result-object v15

    invoke-static {v2, v6, v15}, La/i/a/v;->a(Ljava/util/ArrayList;La/d/a;Ljava/util/Collection;)V

    move-object/from16 v15, v16

    :goto_e
    if-nez v5, :cond_14

    if-nez v11, :cond_14

    if-nez v15, :cond_14

    move-object/from16 v37, v2

    :goto_f
    move-object/from16 v36, v13

    goto/16 :goto_13

    :cond_14
    move-object/from16 v36, v13

    const/4 v13, 0x1

    invoke-static {v12, v14, v0, v10, v13}, La/i/a/v;->c(Landroidx/fragment/app/Fragment;Landroidx/fragment/app/Fragment;ZLa/d/a;Z)V

    if-eqz v15, :cond_16

    invoke-virtual {v2, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {v9, v15, v7, v4}, La/i/a/d0;->j(Ljava/lang/Object;Landroid/view/View;Ljava/util/ArrayList;)V

    iget-boolean v13, v1, La/i/a/v$a;->e:Z

    move-object/from16 v37, v2

    iget-object v2, v1, La/i/a/v$a;->f:La/i/a/a;

    move-object/from16 v16, v9

    move-object/from16 v17, v15

    move-object/from16 v18, v11

    move-object/from16 v19, v10

    move/from16 v20, v13

    move-object/from16 v21, v2

    invoke-static/range {v16 .. v21}, La/i/a/v;->n(La/i/a/d0;Ljava/lang/Object;Ljava/lang/Object;La/d/a;ZLa/i/a/a;)V

    new-instance v2, Landroid/graphics/Rect;

    invoke-direct {v2}, Landroid/graphics/Rect;-><init>()V

    invoke-static {v6, v1, v5, v0}, La/i/a/v;->k(La/d/a;La/i/a/v$a;Ljava/lang/Object;Z)Landroid/view/View;

    move-result-object v1

    if-eqz v1, :cond_15

    move-object v10, v9

    check-cast v10, La/i/a/y;

    if-eqz v5, :cond_15

    .line 10
    move-object v13, v5

    check-cast v13, Landroid/transition/Transition;

    move-object/from16 v16, v1

    new-instance v1, La/i/a/z;

    invoke-direct {v1, v10, v2}, La/i/a/z;-><init>(La/i/a/y;Landroid/graphics/Rect;)V

    invoke-virtual {v13, v1}, Landroid/transition/Transition;->setEpicenterCallback(Landroid/transition/Transition$EpicenterCallback;)V

    goto :goto_10

    :cond_15
    move-object/from16 v16, v1

    :goto_10
    move-object/from16 v29, v2

    move-object/from16 v27, v16

    goto :goto_11

    :cond_16
    move-object/from16 v37, v2

    const/16 v27, 0x0

    const/16 v29, 0x0

    .line 11
    :goto_11
    new-instance v1, La/i/a/t;

    move-object/from16 v22, v1

    move-object/from16 v23, v12

    move-object/from16 v24, v14

    move/from16 v25, v0

    move-object/from16 v26, v6

    move-object/from16 v28, v9

    invoke-direct/range {v22 .. v29}, La/i/a/t;-><init>(Landroidx/fragment/app/Fragment;Landroidx/fragment/app/Fragment;ZLa/d/a;Landroid/view/View;La/i/a/d0;Landroid/graphics/Rect;)V

    invoke-static {v3, v1}, La/f/j/j;->a(Landroid/view/View;Ljava/lang/Runnable;)La/f/j/j;

    goto :goto_14

    :cond_17
    :goto_12
    move-object/from16 v37, v2

    move-object/from16 v35, v6

    move/from16 v34, v10

    goto :goto_f

    :goto_13
    const/4 v15, 0x0

    :goto_14
    if-nez v5, :cond_18

    if-nez v15, :cond_18

    if-nez v11, :cond_18

    goto/16 :goto_c

    .line 12
    :cond_18
    invoke-static {v9, v11, v8, v4, v7}, La/i/a/v;->h(La/i/a/d0;Ljava/lang/Object;Landroidx/fragment/app/Fragment;Ljava/util/ArrayList;Landroid/view/View;)Ljava/util/ArrayList;

    move-result-object v0

    move-object/from16 v1, v35

    move-object/from16 v2, v37

    invoke-static {v9, v5, v1, v2, v7}, La/i/a/v;->h(La/i/a/d0;Ljava/lang/Object;Landroidx/fragment/app/Fragment;Ljava/util/ArrayList;Landroid/view/View;)Ljava/util/ArrayList;

    move-result-object v6

    const/4 v10, 0x4

    invoke-static {v6, v10}, La/i/a/v;->o(Ljava/util/ArrayList;I)V

    move-object/from16 v16, v9

    move-object/from16 v17, v5

    move-object/from16 v18, v11

    move-object/from16 v19, v15

    move-object/from16 v20, v1

    move/from16 v21, v34

    invoke-static/range {v16 .. v21}, La/i/a/v;->m(La/i/a/d0;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Landroidx/fragment/app/Fragment;Z)Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_c

    if-eqz v8, :cond_19

    if-eqz v11, :cond_19

    .line 13
    iget-boolean v10, v8, Landroidx/fragment/app/Fragment;->l:Z

    if-eqz v10, :cond_19

    iget-boolean v10, v8, Landroidx/fragment/app/Fragment;->z:Z

    if-eqz v10, :cond_19

    iget-boolean v10, v8, Landroidx/fragment/app/Fragment;->M:Z

    if-eqz v10, :cond_19

    const/4 v10, 0x1

    invoke-virtual {v8, v10}, Landroidx/fragment/app/Fragment;->F(Z)V

    .line 14
    iget-object v10, v8, Landroidx/fragment/app/Fragment;->G:Landroid/view/View;

    .line 15
    move-object v12, v9

    check-cast v12, La/i/a/y;

    .line 16
    move-object v13, v11

    check-cast v13, Landroid/transition/Transition;

    new-instance v14, La/i/a/x;

    invoke-direct {v14, v12, v10, v0}, La/i/a/x;-><init>(La/i/a/y;Landroid/view/View;Ljava/util/ArrayList;)V

    invoke-virtual {v13, v14}, Landroid/transition/Transition;->addListener(Landroid/transition/Transition$TransitionListener;)Landroid/transition/Transition;

    .line 17
    iget-object v8, v8, Landroidx/fragment/app/Fragment;->F:Landroid/view/ViewGroup;

    new-instance v10, La/i/a/r;

    invoke-direct {v10, v0}, La/i/a/r;-><init>(Ljava/util/ArrayList;)V

    invoke-static {v8, v10}, La/f/j/j;->a(Landroid/view/View;Ljava/lang/Runnable;)La/f/j/j;

    .line 18
    :cond_19
    new-instance v8, Ljava/util/ArrayList;

    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v10

    const/4 v12, 0x0

    :goto_15
    if-ge v12, v10, :cond_1a

    invoke-virtual {v2, v12}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Landroid/view/View;

    invoke-static {v13}, La/f/j/k;->i(Landroid/view/View;)Ljava/lang/String;

    move-result-object v14

    invoke-virtual {v8, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    const/4 v14, 0x0

    .line 19
    invoke-virtual {v13, v14}, Landroid/view/View;->setTransitionName(Ljava/lang/String;)V

    add-int/lit8 v12, v12, 0x1

    goto :goto_15

    :cond_1a
    move-object/from16 v22, v9

    move-object/from16 v23, v1

    move-object/from16 v24, v5

    move-object/from16 v25, v6

    move-object/from16 v26, v11

    move-object/from16 v27, v0

    move-object/from16 v28, v15

    move-object/from16 v29, v2

    .line 20
    invoke-virtual/range {v22 .. v29}, La/i/a/d0;->i(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/ArrayList;Ljava/lang/Object;Ljava/util/ArrayList;Ljava/lang/Object;Ljava/util/ArrayList;)V

    .line 21
    check-cast v1, Landroid/transition/Transition;

    invoke-static {v3, v1}, Landroid/transition/TransitionManager;->beginDelayedTransition(Landroid/view/ViewGroup;Landroid/transition/Transition;)V

    .line 22
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v0

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    const/4 v5, 0x0

    :goto_16
    if-ge v5, v0, :cond_1e

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Landroid/view/View;

    invoke-static {v10}, La/f/j/k;->i(Landroid/view/View;)Ljava/lang/String;

    move-result-object v11

    invoke-virtual {v1, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    if-nez v11, :cond_1b

    move-object/from16 v13, v36

    goto :goto_18

    :cond_1b
    const/4 v14, 0x0

    .line 23
    invoke-virtual {v10, v14}, Landroid/view/View;->setTransitionName(Ljava/lang/String;)V

    move-object/from16 v13, v36

    .line 24
    invoke-virtual {v13, v11, v14}, La/d/h;->getOrDefault(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v10

    .line 25
    check-cast v10, Ljava/lang/String;

    const/4 v12, 0x0

    :goto_17
    if-ge v12, v0, :cond_1d

    invoke-virtual {v8, v12}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v14

    invoke-virtual {v10, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_1c

    invoke-virtual {v2, v12}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Landroid/view/View;

    .line 26
    invoke-virtual {v10, v11}, Landroid/view/View;->setTransitionName(Ljava/lang/String;)V

    goto :goto_18

    :cond_1c
    add-int/lit8 v12, v12, 0x1

    const/4 v14, 0x0

    goto :goto_17

    :cond_1d
    :goto_18
    add-int/lit8 v5, v5, 0x1

    move-object/from16 v36, v13

    goto :goto_16

    .line 27
    :cond_1e
    new-instance v5, La/i/a/a0;

    move-object/from16 v22, v5

    move-object/from16 v23, v9

    move/from16 v24, v0

    move-object/from16 v25, v2

    move-object/from16 v26, v8

    move-object/from16 v27, v4

    move-object/from16 v28, v1

    invoke-direct/range {v22 .. v28}, La/i/a/a0;-><init>(La/i/a/d0;ILjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    invoke-static {v3, v5}, La/f/j/j;->a(Landroid/view/View;Ljava/lang/Runnable;)La/f/j/j;

    const/4 v0, 0x0

    .line 28
    invoke-static {v6, v0}, La/i/a/v;->o(Ljava/util/ArrayList;I)V

    check-cast v9, La/i/a/y;

    .line 29
    check-cast v15, Landroid/transition/TransitionSet;

    if-eqz v15, :cond_1f

    invoke-virtual {v15}, Landroid/transition/TransitionSet;->getTargets()Ljava/util/List;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/List;->clear()V

    invoke-virtual {v15}, Landroid/transition/TransitionSet;->getTargets()Ljava/util/List;

    move-result-object v1

    invoke-interface {v1, v2}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    invoke-virtual {v9, v15, v4, v2}, La/i/a/y;->h(Ljava/lang/Object;Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    :cond_1f
    :goto_19
    move-object/from16 v2, p0

    goto :goto_1b

    :cond_20
    move-object v2, v0

    move-object/from16 v31, v5

    move/from16 v32, v14

    move/from16 v33, v15

    const/4 v0, 0x0

    .line 30
    iget-object v3, v2, La/i/a/j;->q:La/i/a/e;

    invoke-virtual {v3}, La/i/a/e;->f()Z

    move-result v3

    if-eqz v3, :cond_21

    iget-object v3, v2, La/i/a/j;->q:La/i/a/e;

    invoke-virtual {v3, v9}, La/i/a/e;->b(I)Landroid/view/View;

    move-result-object v3

    move-object v14, v3

    check-cast v14, Landroid/view/ViewGroup;

    move-object v3, v14

    goto :goto_1a

    :cond_21
    const/4 v3, 0x0

    :goto_1a
    if-nez v3, :cond_22

    goto :goto_1b

    :cond_22
    iget-object v4, v1, La/i/a/v$a;->a:Landroidx/fragment/app/Fragment;

    iget-object v5, v1, La/i/a/v$a;->d:Landroidx/fragment/app/Fragment;

    invoke-static {v5, v4}, La/i/a/v;->g(Landroidx/fragment/app/Fragment;Landroidx/fragment/app/Fragment;)La/i/a/d0;

    move-result-object v6

    if-nez v6, :cond_23

    :goto_1b
    move/from16 v27, v32

    move/from16 v30, v33

    goto/16 :goto_22

    :cond_23
    iget-boolean v8, v1, La/i/a/v$a;->b:Z

    iget-boolean v9, v1, La/i/a/v$a;->e:Z

    invoke-static {v6, v4, v8}, La/i/a/v;->i(La/i/a/d0;Landroidx/fragment/app/Fragment;Z)Ljava/lang/Object;

    move-result-object v8

    invoke-static {v6, v5, v9}, La/i/a/v;->j(La/i/a/d0;Landroidx/fragment/app/Fragment;Z)Ljava/lang/Object;

    move-result-object v12

    new-instance v11, Ljava/util/ArrayList;

    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    new-instance v10, Ljava/util/ArrayList;

    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 31
    iget-object v9, v1, La/i/a/v$a;->a:Landroidx/fragment/app/Fragment;

    iget-object v15, v1, La/i/a/v$a;->d:Landroidx/fragment/app/Fragment;

    if-eqz v9, :cond_2a

    if-nez v15, :cond_24

    goto/16 :goto_1f

    :cond_24
    iget-boolean v14, v1, La/i/a/v$a;->b:Z

    invoke-virtual {v13}, La/d/h;->isEmpty()Z

    move-result v16

    if-eqz v16, :cond_25

    const/4 v0, 0x0

    goto :goto_1c

    :cond_25
    invoke-static {v6, v9, v15, v14}, La/i/a/v;->l(La/i/a/d0;Landroidx/fragment/app/Fragment;Landroidx/fragment/app/Fragment;Z)Ljava/lang/Object;

    move-result-object v16

    move-object/from16 v0, v16

    :goto_1c
    invoke-static {v6, v13, v0, v1}, La/i/a/v;->f(La/i/a/d0;La/d/a;Ljava/lang/Object;La/i/a/v$a;)La/d/a;

    move-result-object v2

    invoke-virtual {v13}, La/d/h;->isEmpty()Z

    move-result v16

    if-eqz v16, :cond_26

    const/4 v0, 0x0

    goto :goto_1d

    :cond_26
    move-object/from16 v16, v0

    invoke-virtual {v2}, La/d/a;->values()Ljava/util/Collection;

    move-result-object v0

    invoke-virtual {v11, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    move-object/from16 v0, v16

    :goto_1d
    if-nez v8, :cond_27

    if-nez v12, :cond_27

    if-nez v0, :cond_27

    goto/16 :goto_1f

    :cond_27
    move-object/from16 v22, v4

    const/4 v4, 0x1

    invoke-static {v9, v15, v14, v2, v4}, La/i/a/v;->c(Landroidx/fragment/app/Fragment;Landroidx/fragment/app/Fragment;ZLa/d/a;Z)V

    if-eqz v0, :cond_28

    new-instance v4, Landroid/graphics/Rect;

    invoke-direct {v4}, Landroid/graphics/Rect;-><init>()V

    invoke-virtual {v6, v0, v7, v11}, La/i/a/d0;->j(Ljava/lang/Object;Landroid/view/View;Ljava/util/ArrayList;)V

    move-object/from16 v20, v9

    iget-boolean v9, v1, La/i/a/v$a;->e:Z

    move-object/from16 v21, v10

    iget-object v10, v1, La/i/a/v$a;->f:La/i/a/a;

    move/from16 v23, v14

    move-object v14, v6

    move-object/from16 v24, v15

    move-object v15, v0

    move-object/from16 v16, v12

    move-object/from16 v17, v2

    move/from16 v18, v9

    move-object/from16 v19, v10

    invoke-static/range {v14 .. v19}, La/i/a/v;->n(La/i/a/d0;Ljava/lang/Object;Ljava/lang/Object;La/d/a;ZLa/i/a/a;)V

    if-eqz v8, :cond_29

    move-object v2, v6

    check-cast v2, La/i/a/y;

    .line 32
    move-object v9, v8

    check-cast v9, Landroid/transition/Transition;

    new-instance v10, La/i/a/z;

    invoke-direct {v10, v2, v4}, La/i/a/z;-><init>(La/i/a/y;Landroid/graphics/Rect;)V

    invoke-virtual {v9, v10}, Landroid/transition/Transition;->setEpicenterCallback(Landroid/transition/Transition$EpicenterCallback;)V

    goto :goto_1e

    :cond_28
    move-object/from16 v20, v9

    move-object/from16 v21, v10

    move/from16 v23, v14

    move-object/from16 v24, v15

    const/4 v4, 0x0

    .line 33
    :cond_29
    :goto_1e
    new-instance v2, La/i/a/u;

    move-object/from16 v16, v20

    move-object v9, v2

    move-object/from16 v15, v21

    move-object v10, v6

    move-object v14, v11

    move-object v11, v13

    move-object/from16 v25, v5

    move-object v5, v12

    move-object v12, v0

    move-object/from16 v26, v0

    move-object v0, v13

    move-object v13, v1

    move-object/from16 v28, v14

    move/from16 v27, v32

    const/16 v29, 0x0

    move-object v14, v15

    move-object/from16 v32, v15

    move/from16 v30, v33

    move-object v15, v7

    move-object/from16 v17, v24

    move/from16 v18, v23

    move-object/from16 v19, v28

    move-object/from16 v20, v8

    move-object/from16 v21, v4

    invoke-direct/range {v9 .. v21}, La/i/a/u;-><init>(La/i/a/d0;La/d/a;Ljava/lang/Object;La/i/a/v$a;Ljava/util/ArrayList;Landroid/view/View;Landroidx/fragment/app/Fragment;Landroidx/fragment/app/Fragment;ZLjava/util/ArrayList;Ljava/lang/Object;Landroid/graphics/Rect;)V

    invoke-static {v3, v2}, La/f/j/j;->a(Landroid/view/View;Ljava/lang/Runnable;)La/f/j/j;

    move-object/from16 v20, v26

    goto :goto_20

    :cond_2a
    :goto_1f
    move-object/from16 v22, v4

    move-object/from16 v25, v5

    move-object/from16 v28, v11

    move-object v5, v12

    move-object v0, v13

    move/from16 v27, v32

    move/from16 v30, v33

    const/16 v29, 0x0

    move-object/from16 v32, v10

    move-object/from16 v20, v29

    :goto_20
    if-nez v8, :cond_2b

    if-nez v20, :cond_2b

    if-nez v5, :cond_2b

    goto/16 :goto_22

    :cond_2b
    move-object/from16 v2, v25

    move-object/from16 v4, v28

    .line 34
    invoke-static {v6, v5, v2, v4, v7}, La/i/a/v;->h(La/i/a/d0;Ljava/lang/Object;Landroidx/fragment/app/Fragment;Ljava/util/ArrayList;Landroid/view/View;)Ljava/util/ArrayList;

    move-result-object v2

    if-eqz v2, :cond_2d

    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v4

    if-eqz v4, :cond_2c

    goto :goto_21

    :cond_2c
    move-object/from16 v29, v5

    :cond_2d
    :goto_21
    if-eqz v8, :cond_2e

    .line 35
    move-object v4, v8

    check-cast v4, Landroid/transition/Transition;

    invoke-virtual {v4, v7}, Landroid/transition/Transition;->addTarget(Landroid/view/View;)Landroid/transition/Transition;

    .line 36
    :cond_2e
    iget-boolean v1, v1, La/i/a/v$a;->b:Z

    move-object v14, v6

    move-object v15, v8

    move-object/from16 v16, v29

    move-object/from16 v17, v20

    move-object/from16 v18, v22

    move/from16 v19, v1

    invoke-static/range {v14 .. v19}, La/i/a/v;->m(La/i/a/d0;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Landroidx/fragment/app/Fragment;Z)Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_2f

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    move-object v14, v6

    move-object v15, v1

    move-object/from16 v16, v8

    move-object/from16 v17, v4

    move-object/from16 v18, v29

    move-object/from16 v19, v2

    move-object/from16 v21, v32

    invoke-virtual/range {v14 .. v21}, La/i/a/d0;->i(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/ArrayList;Ljava/lang/Object;Ljava/util/ArrayList;Ljava/lang/Object;Ljava/util/ArrayList;)V

    .line 37
    new-instance v5, La/i/a/s;

    move-object v9, v5

    move-object v10, v8

    move-object v11, v6

    move-object v12, v7

    move-object/from16 v13, v22

    move-object/from16 v14, v32

    move-object v15, v4

    move-object/from16 v16, v2

    move-object/from16 v17, v29

    invoke-direct/range {v9 .. v17}, La/i/a/s;-><init>(Ljava/lang/Object;La/i/a/d0;Landroid/view/View;Landroidx/fragment/app/Fragment;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/lang/Object;)V

    invoke-static {v3, v5}, La/f/j/j;->a(Landroid/view/View;Ljava/lang/Runnable;)La/f/j/j;

    .line 38
    new-instance v2, La/i/a/b0;

    move-object/from16 v4, v32

    invoke-direct {v2, v6, v4, v0}, La/i/a/b0;-><init>(La/i/a/d0;Ljava/util/ArrayList;Ljava/util/Map;)V

    invoke-static {v3, v2}, La/f/j/j;->a(Landroid/view/View;Ljava/lang/Runnable;)La/f/j/j;

    .line 39
    check-cast v1, Landroid/transition/Transition;

    invoke-static {v3, v1}, Landroid/transition/TransitionManager;->beginDelayedTransition(Landroid/view/ViewGroup;Landroid/transition/Transition;)V

    .line 40
    new-instance v1, La/i/a/c0;

    invoke-direct {v1, v6, v4, v0}, La/i/a/c0;-><init>(La/i/a/d0;Ljava/util/ArrayList;Ljava/util/Map;)V

    invoke-static {v3, v1}, La/f/j/j;->a(Landroid/view/View;Ljava/lang/Runnable;)La/f/j/j;

    :cond_2f
    :goto_22
    add-int/lit8 v14, v27, 0x1

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move/from16 v3, p4

    move/from16 v4, p5

    move/from16 v15, v30

    move-object/from16 v5, v31

    const/4 v6, 0x1

    const/4 v8, 0x0

    goto/16 :goto_4

    :cond_30
    return-void
.end method
