.class public La/f/g/b;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/f/g/b$e;,
        La/f/g/b$f;,
        La/f/g/b$g;
    }
.end annotation


# static fields
.field public static final a:La/d/f;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "La/d/f<",
            "Ljava/lang/String;",
            "Landroid/graphics/Typeface;",
            ">;"
        }
    .end annotation
.end field

.field public static final b:La/f/g/c;

.field public static final c:Ljava/lang/Object;

.field public static final d:La/d/h;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "La/d/h<",
            "Ljava/lang/String;",
            "Ljava/util/ArrayList<",
            "La/f/g/c$c<",
            "La/f/g/b$g;",
            ">;>;>;"
        }
    .end annotation
.end field

.field public static final e:Ljava/util/Comparator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Comparator<",
            "[B>;"
        }
    .end annotation
.end field


# direct methods
.method public static constructor <clinit>()V
    .locals 4

    new-instance v0, La/d/f;

    const/16 v1, 0x10

    invoke-direct {v0, v1}, La/d/f;-><init>(I)V

    sput-object v0, La/f/g/b;->a:La/d/f;

    new-instance v0, La/f/g/c;

    const-string v1, "fonts"

    const/16 v2, 0xa

    const/16 v3, 0x2710

    invoke-direct {v0, v1, v2, v3}, La/f/g/c;-><init>(Ljava/lang/String;II)V

    sput-object v0, La/f/g/b;->b:La/f/g/c;

    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, La/f/g/b;->c:Ljava/lang/Object;

    new-instance v0, La/d/h;

    invoke-direct {v0}, La/d/h;-><init>()V

    sput-object v0, La/f/g/b;->d:La/d/h;

    new-instance v0, La/f/g/b$d;

    invoke-direct {v0}, La/f/g/b$d;-><init>()V

    sput-object v0, La/f/g/b;->e:Ljava/util/Comparator;

    return-void
.end method

.method public static a(Landroid/content/Context;Landroid/os/CancellationSignal;La/f/g/a;)La/f/g/b$e;
    .locals 20

    move-object/from16 v0, p2

    invoke-virtual/range {p0 .. p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v1

    invoke-virtual/range {p0 .. p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v2

    .line 1
    iget-object v3, v0, La/f/g/a;->a:Ljava/lang/String;

    const/4 v4, 0x0

    .line 2
    invoke-virtual {v1, v3, v4}, Landroid/content/pm/PackageManager;->resolveContentProvider(Ljava/lang/String;I)Landroid/content/pm/ProviderInfo;

    move-result-object v5

    if-eqz v5, :cond_11

    iget-object v6, v5, Landroid/content/pm/ProviderInfo;->packageName:Ljava/lang/String;

    .line 3
    iget-object v7, v0, La/f/g/a;->b:Ljava/lang/String;

    .line 4
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_10

    iget-object v3, v5, Landroid/content/pm/ProviderInfo;->packageName:Ljava/lang/String;

    const/16 v6, 0x40

    invoke-virtual {v1, v3, v6}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    move-result-object v1

    iget-object v1, v1, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    .line 5
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    move v6, v4

    :goto_0
    array-length v7, v1

    if-ge v6, v7, :cond_0

    aget-object v7, v1, v6

    invoke-virtual {v7}, Landroid/content/pm/Signature;->toByteArray()[B

    move-result-object v7

    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    .line 6
    :cond_0
    sget-object v1, La/f/g/b;->e:Ljava/util/Comparator;

    invoke-static {v3, v1}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 7
    iget-object v1, v0, La/f/g/a;->d:Ljava/util/List;

    if-eqz v1, :cond_1

    goto :goto_1

    .line 8
    :cond_1
    iget v1, v0, La/f/g/a;->e:I

    .line 9
    invoke-static {v2, v1}, La/b/k/h$i;->w(Landroid/content/res/Resources;I)Ljava/util/List;

    move-result-object v1

    :goto_1
    move v2, v4

    .line 10
    :goto_2
    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v6

    const/4 v7, 0x0

    const/4 v8, 0x1

    if-ge v2, v6, :cond_6

    new-instance v6, Ljava/util/ArrayList;

    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/util/Collection;

    invoke-direct {v6, v9}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    sget-object v9, La/f/g/b;->e:Ljava/util/Comparator;

    invoke-static {v6, v9}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 11
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v9

    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    move-result v10

    if-eq v9, v10, :cond_2

    goto :goto_4

    :cond_2
    move v9, v4

    :goto_3
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v10

    if-ge v9, v10, :cond_4

    invoke-virtual {v3, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, [B

    invoke-virtual {v6, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, [B

    invoke-static {v10, v11}, Ljava/util/Arrays;->equals([B[B)Z

    move-result v10

    if-nez v10, :cond_3

    :goto_4
    move v6, v4

    goto :goto_5

    :cond_3
    add-int/lit8 v9, v9, 0x1

    goto :goto_3

    :cond_4
    move v6, v8

    :goto_5
    if-eqz v6, :cond_5

    goto :goto_6

    :cond_5
    add-int/lit8 v2, v2, 0x1

    goto :goto_2

    :cond_6
    move-object v5, v7

    :goto_6
    if-nez v5, :cond_7

    .line 12
    new-instance v0, La/f/g/b$e;

    invoke-direct {v0, v8, v7}, La/f/g/b$e;-><init>(I[La/f/g/b$f;)V

    return-object v0

    :cond_7
    iget-object v1, v5, Landroid/content/pm/ProviderInfo;->authority:Ljava/lang/String;

    .line 13
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    new-instance v3, Landroid/net/Uri$Builder;

    invoke-direct {v3}, Landroid/net/Uri$Builder;-><init>()V

    const-string v5, "content"

    invoke-virtual {v3, v5}, Landroid/net/Uri$Builder;->scheme(Ljava/lang/String;)Landroid/net/Uri$Builder;

    move-result-object v3

    invoke-virtual {v3, v1}, Landroid/net/Uri$Builder;->authority(Ljava/lang/String;)Landroid/net/Uri$Builder;

    move-result-object v3

    invoke-virtual {v3}, Landroid/net/Uri$Builder;->build()Landroid/net/Uri;

    move-result-object v3

    new-instance v6, Landroid/net/Uri$Builder;

    invoke-direct {v6}, Landroid/net/Uri$Builder;-><init>()V

    invoke-virtual {v6, v5}, Landroid/net/Uri$Builder;->scheme(Ljava/lang/String;)Landroid/net/Uri$Builder;

    move-result-object v5

    invoke-virtual {v5, v1}, Landroid/net/Uri$Builder;->authority(Ljava/lang/String;)Landroid/net/Uri$Builder;

    move-result-object v1

    const-string v5, "file"

    invoke-virtual {v1, v5}, Landroid/net/Uri$Builder;->appendPath(Ljava/lang/String;)Landroid/net/Uri$Builder;

    move-result-object v1

    invoke-virtual {v1}, Landroid/net/Uri$Builder;->build()Landroid/net/Uri;

    move-result-object v1

    :try_start_0
    invoke-virtual/range {p0 .. p0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v9

    const-string v10, "_id"

    const-string v11, "file_id"

    const-string v12, "font_ttc_index"

    const-string v13, "font_variation_settings"

    const-string v14, "font_weight"

    const-string v15, "font_italic"

    const-string v16, "result_code"

    filled-new-array/range {v10 .. v16}, [Ljava/lang/String;

    move-result-object v11

    const-string v12, "query = ?"

    new-array v13, v8, [Ljava/lang/String;

    .line 14
    iget-object v0, v0, La/f/g/a;->c:Ljava/lang/String;

    aput-object v0, v13, v4

    const/4 v14, 0x0

    const/4 v15, 0x0

    move-object v10, v3

    .line 15
    invoke-virtual/range {v9 .. v15}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;

    move-result-object v7

    if-eqz v7, :cond_d

    invoke-interface {v7}, Landroid/database/Cursor;->getCount()I

    move-result v0

    if-lez v0, :cond_d

    const-string v0, "result_code"

    invoke-interface {v7, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v0

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    const-string v5, "_id"

    invoke-interface {v7, v5}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v5

    const-string v6, "file_id"

    invoke-interface {v7, v6}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v6

    const-string v9, "font_ttc_index"

    invoke-interface {v7, v9}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v9

    const-string v10, "font_weight"

    invoke-interface {v7, v10}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v10

    const-string v11, "font_italic"

    invoke-interface {v7, v11}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v11

    :goto_7
    invoke-interface {v7}, Landroid/database/Cursor;->moveToNext()Z

    move-result v12

    if-eqz v12, :cond_d

    const/4 v12, -0x1

    if-eq v0, v12, :cond_8

    invoke-interface {v7, v0}, Landroid/database/Cursor;->getInt(I)I

    move-result v13

    move/from16 v19, v13

    goto :goto_8

    :cond_8
    move/from16 v19, v4

    :goto_8
    if-eq v9, v12, :cond_9

    invoke-interface {v7, v9}, Landroid/database/Cursor;->getInt(I)I

    move-result v13

    move/from16 v16, v13

    goto :goto_9

    :cond_9
    move/from16 v16, v4

    :goto_9
    if-ne v6, v12, :cond_a

    invoke-interface {v7, v5}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v13

    invoke-static {v3, v13, v14}, Landroid/content/ContentUris;->withAppendedId(Landroid/net/Uri;J)Landroid/net/Uri;

    move-result-object v13

    goto :goto_a

    :cond_a
    invoke-interface {v7, v6}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v13

    invoke-static {v1, v13, v14}, Landroid/content/ContentUris;->withAppendedId(Landroid/net/Uri;J)Landroid/net/Uri;

    move-result-object v13

    :goto_a
    move-object v15, v13

    if-eq v10, v12, :cond_b

    invoke-interface {v7, v10}, Landroid/database/Cursor;->getInt(I)I

    move-result v13

    goto :goto_b

    :cond_b
    const/16 v13, 0x190

    :goto_b
    move/from16 v17, v13

    if-eq v11, v12, :cond_c

    invoke-interface {v7, v11}, Landroid/database/Cursor;->getInt(I)I

    move-result v12

    if-ne v12, v8, :cond_c

    move/from16 v18, v8

    goto :goto_c

    :cond_c
    move/from16 v18, v4

    :goto_c
    new-instance v12, La/f/g/b$f;

    move-object v14, v12

    invoke-direct/range {v14 .. v19}, La/f/g/b$f;-><init>(Landroid/net/Uri;IIZI)V

    invoke-virtual {v2, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_7

    :cond_d
    if-eqz v7, :cond_e

    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    :cond_e
    new-array v0, v4, [La/f/g/b$f;

    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [La/f/g/b$f;

    .line 16
    new-instance v1, La/f/g/b$e;

    invoke-direct {v1, v4, v0}, La/f/g/b$e;-><init>(I[La/f/g/b$f;)V

    return-object v1

    :catchall_0
    move-exception v0

    if-eqz v7, :cond_f

    .line 17
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    :cond_f
    throw v0

    .line 18
    :cond_10
    new-instance v1, Landroid/content/pm/PackageManager$NameNotFoundException;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "Found content provider "

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, ", but package was not "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    iget-object v0, v0, La/f/g/a;->b:Ljava/lang/String;

    .line 20
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Landroid/content/pm/PackageManager$NameNotFoundException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_11
    new-instance v0, Landroid/content/pm/PackageManager$NameNotFoundException;

    const-string v1, "No package found for authority: "

    invoke-static {v1, v3}, Lb/a/a/a/a;->a(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Landroid/content/pm/PackageManager$NameNotFoundException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static b(Landroid/content/Context;La/f/g/a;I)La/f/g/b$g;
    .locals 3

    const/4 v0, 0x0

    :try_start_0
    invoke-static {p0, v0, p1}, La/f/g/b;->a(Landroid/content/Context;Landroid/os/CancellationSignal;La/f/g/a;)La/f/g/b$e;

    move-result-object p1
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 1
    iget v1, p1, La/f/g/b$e;->a:I

    const/4 v2, -0x3

    if-nez v1, :cond_1

    .line 2
    iget-object p1, p1, La/f/g/b$e;->b:[La/f/g/b$f;

    .line 3
    sget-object v1, La/f/e/c;->a:La/f/e/i;

    invoke-virtual {v1, p0, v0, p1, p2}, La/f/e/i;->b(Landroid/content/Context;Landroid/os/CancellationSignal;[La/f/g/b$f;I)Landroid/graphics/Typeface;

    move-result-object p0

    .line 4
    new-instance p1, La/f/g/b$g;

    if-eqz p0, :cond_0

    const/4 v2, 0x0

    :cond_0
    invoke-direct {p1, p0, v2}, La/f/g/b$g;-><init>(Landroid/graphics/Typeface;I)V

    return-object p1

    :cond_1
    const/4 p0, 0x1

    if-ne v1, p0, :cond_2

    const/4 v2, -0x2

    :cond_2
    new-instance p0, La/f/g/b$g;

    invoke-direct {p0, v0, v2}, La/f/g/b$g;-><init>(Landroid/graphics/Typeface;I)V

    return-object p0

    :catch_0
    new-instance p0, La/f/g/b$g;

    const/4 p1, -0x1

    invoke-direct {p0, v0, p1}, La/f/g/b$g;-><init>(Landroid/graphics/Typeface;I)V

    return-object p0
.end method

.method public static c(Landroid/content/Context;La/f/g/a;La/f/d/b/e;Landroid/os/Handler;ZII)Landroid/graphics/Typeface;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 1
    iget-object v1, p1, La/f/g/a;->f:Ljava/lang/String;

    .line 2
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "-"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    sget-object v1, La/f/g/b;->a:La/d/f;

    invoke-virtual {v1, v0}, La/d/f;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/graphics/Typeface;

    if-eqz v1, :cond_1

    if-eqz p2, :cond_0

    invoke-virtual {p2, v1}, La/f/d/b/e;->c(Landroid/graphics/Typeface;)V

    :cond_0
    return-object v1

    :cond_1
    if-eqz p4, :cond_4

    const/4 v1, -0x1

    if-ne p5, v1, :cond_4

    invoke-static {p0, p1, p6}, La/f/g/b;->b(Landroid/content/Context;La/f/g/a;I)La/f/g/b$g;

    move-result-object p0

    if-eqz p2, :cond_3

    iget p1, p0, La/f/g/b$g;->b:I

    if-nez p1, :cond_2

    iget-object p1, p0, La/f/g/b$g;->a:Landroid/graphics/Typeface;

    invoke-virtual {p2, p1, p3}, La/f/d/b/e;->b(Landroid/graphics/Typeface;Landroid/os/Handler;)V

    goto :goto_0

    :cond_2
    invoke-virtual {p2, p1, p3}, La/f/d/b/e;->a(ILandroid/os/Handler;)V

    :cond_3
    :goto_0
    iget-object p0, p0, La/f/g/b$g;->a:Landroid/graphics/Typeface;

    return-object p0

    :cond_4
    new-instance v1, La/f/g/b$a;

    invoke-direct {v1, p0, p1, p6, v0}, La/f/g/b$a;-><init>(Landroid/content/Context;La/f/g/a;ILjava/lang/String;)V

    const/4 p0, 0x0

    if-eqz p4, :cond_5

    :try_start_0
    sget-object p1, La/f/g/b;->b:La/f/g/c;

    invoke-virtual {p1, v1, p5}, La/f/g/c;->b(Ljava/util/concurrent/Callable;I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, La/f/g/b$g;

    iget-object p0, p1, La/f/g/b$g;->a:Landroid/graphics/Typeface;
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    return-object p0

    :cond_5
    if-nez p2, :cond_6

    move-object p1, p0

    goto :goto_1

    :cond_6
    new-instance p1, La/f/g/b$b;

    invoke-direct {p1, p2, p3}, La/f/g/b$b;-><init>(La/f/d/b/e;Landroid/os/Handler;)V

    :goto_1
    sget-object p2, La/f/g/b;->c:Ljava/lang/Object;

    monitor-enter p2

    :try_start_1
    sget-object p3, La/f/g/b;->d:La/d/h;

    .line 3
    invoke-virtual {p3, v0, p0}, La/d/h;->getOrDefault(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p3

    .line 4
    check-cast p3, Ljava/util/ArrayList;

    if-eqz p3, :cond_8

    if-eqz p1, :cond_7

    invoke-virtual {p3, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_7
    monitor-exit p2

    return-object p0

    :cond_8
    if-eqz p1, :cond_9

    new-instance p3, Ljava/util/ArrayList;

    invoke-direct {p3}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {p3, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    sget-object p1, La/f/g/b;->d:La/d/h;

    invoke-virtual {p1, v0, p3}, La/d/h;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_9
    monitor-exit p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    sget-object p1, La/f/g/b;->b:La/f/g/c;

    new-instance p2, La/f/g/b$c;

    invoke-direct {p2, v0}, La/f/g/b$c;-><init>(Ljava/lang/String;)V

    if-eqz p1, :cond_a

    .line 5
    new-instance p3, Landroid/os/Handler;

    invoke-direct {p3}, Landroid/os/Handler;-><init>()V

    new-instance p4, La/f/g/d;

    invoke-direct {p4, p1, v1, p3, p2}, La/f/g/d;-><init>(La/f/g/c;Ljava/util/concurrent/Callable;Landroid/os/Handler;La/f/g/c$c;)V

    invoke-virtual {p1, p4}, La/f/g/c;->a(Ljava/lang/Runnable;)V

    return-object p0

    :cond_a
    throw p0

    :catchall_0
    move-exception p0

    .line 6
    :try_start_2
    monitor-exit p2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw p0
.end method

.method public static d(Landroid/content/Context;[La/f/g/b$f;Landroid/os/CancellationSignal;)Ljava/util/Map;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            "[",
            "La/f/g/b$f;",
            "Landroid/os/CancellationSignal;",
            ")",
            "Ljava/util/Map<",
            "Landroid/net/Uri;",
            "Ljava/nio/ByteBuffer;",
            ">;"
        }
    .end annotation

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    array-length v1, p1

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_2

    aget-object v3, p1, v2

    .line 1
    iget v4, v3, La/f/g/b$f;->e:I

    if-eqz v4, :cond_0

    goto :goto_1

    .line 2
    :cond_0
    iget-object v3, v3, La/f/g/b$f;->a:Landroid/net/Uri;

    .line 3
    invoke-virtual {v0, v3}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1

    goto :goto_1

    :cond_1
    invoke-static {p0, p2, v3}, La/b/k/h$i;->p(Landroid/content/Context;Landroid/os/CancellationSignal;Landroid/net/Uri;)Ljava/nio/ByteBuffer;

    move-result-object v4

    invoke-virtual {v0, v3, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :goto_1
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_2
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    move-result-object p0

    return-object p0
.end method
