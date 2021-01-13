.class public abstract La/g/a/a;
.super Landroid/widget/BaseAdapter;
.source ""

# interfaces
.implements Landroid/widget/Filterable;
.implements La/g/a/b$a;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/g/a/a$b;,
        La/g/a/a$a;
    }
.end annotation


# instance fields
.field public b:Z

.field public c:Z

.field public d:Landroid/database/Cursor;

.field public e:Landroid/content/Context;

.field public f:I

.field public g:La/g/a/a$a;

.field public h:Landroid/database/DataSetObserver;

.field public i:La/g/a/b;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/database/Cursor;Z)V
    .locals 4

    invoke-direct {p0}, Landroid/widget/BaseAdapter;-><init>()V

    const/4 v0, 0x1

    const/4 v1, 0x2

    if-eqz p3, :cond_0

    move p3, v0

    goto :goto_0

    :cond_0
    move p3, v1

    :goto_0
    and-int/lit8 v2, p3, 0x1

    const/4 v3, 0x0

    if-ne v2, v0, :cond_1

    or-int/lit8 p3, p3, 0x2

    .line 1
    iput-boolean v0, p0, La/g/a/a;->c:Z

    goto :goto_1

    :cond_1
    iput-boolean v3, p0, La/g/a/a;->c:Z

    :goto_1
    if-eqz p2, :cond_2

    goto :goto_2

    :cond_2
    move v0, v3

    :goto_2
    iput-object p2, p0, La/g/a/a;->d:Landroid/database/Cursor;

    iput-boolean v0, p0, La/g/a/a;->b:Z

    iput-object p1, p0, La/g/a/a;->e:Landroid/content/Context;

    if-eqz v0, :cond_3

    const-string p1, "_id"

    invoke-interface {p2, p1}, Landroid/database/Cursor;->getColumnIndexOrThrow(Ljava/lang/String;)I

    move-result p1

    goto :goto_3

    :cond_3
    const/4 p1, -0x1

    :goto_3
    iput p1, p0, La/g/a/a;->f:I

    and-int/lit8 p1, p3, 0x2

    if-ne p1, v1, :cond_4

    new-instance p1, La/g/a/a$a;

    invoke-direct {p1, p0}, La/g/a/a$a;-><init>(La/g/a/a;)V

    iput-object p1, p0, La/g/a/a;->g:La/g/a/a$a;

    new-instance p1, La/g/a/a$b;

    invoke-direct {p1, p0}, La/g/a/a$b;-><init>(La/g/a/a;)V

    goto :goto_4

    :cond_4
    const/4 p1, 0x0

    iput-object p1, p0, La/g/a/a;->g:La/g/a/a$a;

    :goto_4
    iput-object p1, p0, La/g/a/a;->h:Landroid/database/DataSetObserver;

    if-eqz v0, :cond_6

    iget-object p1, p0, La/g/a/a;->g:La/g/a/a$a;

    if-eqz p1, :cond_5

    invoke-interface {p2, p1}, Landroid/database/Cursor;->registerContentObserver(Landroid/database/ContentObserver;)V

    :cond_5
    iget-object p1, p0, La/g/a/a;->h:Landroid/database/DataSetObserver;

    if-eqz p1, :cond_6

    invoke-interface {p2, p1}, Landroid/database/Cursor;->registerDataSetObserver(Landroid/database/DataSetObserver;)V

    :cond_6
    return-void
.end method


# virtual methods
.method public abstract a(Landroid/view/View;Landroid/content/Context;Landroid/database/Cursor;)V
.end method

.method public b(Landroid/database/Cursor;)V
    .locals 2

    .line 1
    iget-object v0, p0, La/g/a/a;->d:Landroid/database/Cursor;

    if-ne p1, v0, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    :cond_0
    if-eqz v0, :cond_2

    iget-object v1, p0, La/g/a/a;->g:La/g/a/a$a;

    if-eqz v1, :cond_1

    invoke-interface {v0, v1}, Landroid/database/Cursor;->unregisterContentObserver(Landroid/database/ContentObserver;)V

    :cond_1
    iget-object v1, p0, La/g/a/a;->h:Landroid/database/DataSetObserver;

    if-eqz v1, :cond_2

    invoke-interface {v0, v1}, Landroid/database/Cursor;->unregisterDataSetObserver(Landroid/database/DataSetObserver;)V

    :cond_2
    iput-object p1, p0, La/g/a/a;->d:Landroid/database/Cursor;

    if-eqz p1, :cond_5

    iget-object v1, p0, La/g/a/a;->g:La/g/a/a$a;

    if-eqz v1, :cond_3

    invoke-interface {p1, v1}, Landroid/database/Cursor;->registerContentObserver(Landroid/database/ContentObserver;)V

    :cond_3
    iget-object v1, p0, La/g/a/a;->h:Landroid/database/DataSetObserver;

    if-eqz v1, :cond_4

    invoke-interface {p1, v1}, Landroid/database/Cursor;->registerDataSetObserver(Landroid/database/DataSetObserver;)V

    :cond_4
    const-string v1, "_id"

    invoke-interface {p1, v1}, Landroid/database/Cursor;->getColumnIndexOrThrow(Ljava/lang/String;)I

    move-result p1

    iput p1, p0, La/g/a/a;->f:I

    const/4 p1, 0x1

    iput-boolean p1, p0, La/g/a/a;->b:Z

    invoke-virtual {p0}, Landroid/widget/BaseAdapter;->notifyDataSetChanged()V

    goto :goto_0

    :cond_5
    const/4 p1, -0x1

    iput p1, p0, La/g/a/a;->f:I

    const/4 p1, 0x0

    iput-boolean p1, p0, La/g/a/a;->b:Z

    invoke-virtual {p0}, Landroid/widget/BaseAdapter;->notifyDataSetInvalidated()V

    :goto_0
    if-eqz v0, :cond_6

    .line 2
    invoke-interface {v0}, Landroid/database/Cursor;->close()V

    :cond_6
    return-void
.end method

.method public abstract c(Landroid/database/Cursor;)Ljava/lang/CharSequence;
.end method

.method public abstract d(Landroid/content/Context;Landroid/database/Cursor;Landroid/view/ViewGroup;)Landroid/view/View;
.end method

.method public getCount()I
    .locals 1

    iget-boolean v0, p0, La/g/a/a;->b:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, La/g/a/a;->d:Landroid/database/Cursor;

    if-eqz v0, :cond_0

    invoke-interface {v0}, Landroid/database/Cursor;->getCount()I

    move-result v0

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public getDropDownView(ILandroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;
    .locals 1

    iget-boolean v0, p0, La/g/a/a;->b:Z

    if-eqz v0, :cond_1

    iget-object v0, p0, La/g/a/a;->d:Landroid/database/Cursor;

    invoke-interface {v0, p1}, Landroid/database/Cursor;->moveToPosition(I)Z

    if-nez p2, :cond_0

    move-object p1, p0

    check-cast p1, La/g/a/c;

    .line 1
    iget-object p2, p1, La/g/a/c;->l:Landroid/view/LayoutInflater;

    iget p1, p1, La/g/a/c;->k:I

    const/4 v0, 0x0

    invoke-virtual {p2, p1, p3, v0}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    move-result-object p2

    .line 2
    :cond_0
    iget-object p1, p0, La/g/a/a;->e:Landroid/content/Context;

    iget-object p3, p0, La/g/a/a;->d:Landroid/database/Cursor;

    invoke-virtual {p0, p2, p1, p3}, La/g/a/a;->a(Landroid/view/View;Landroid/content/Context;Landroid/database/Cursor;)V

    return-object p2

    :cond_1
    const/4 p1, 0x0

    return-object p1
.end method

.method public getFilter()Landroid/widget/Filter;
    .locals 1

    iget-object v0, p0, La/g/a/a;->i:La/g/a/b;

    if-nez v0, :cond_0

    new-instance v0, La/g/a/b;

    invoke-direct {v0, p0}, La/g/a/b;-><init>(La/g/a/b$a;)V

    iput-object v0, p0, La/g/a/a;->i:La/g/a/b;

    :cond_0
    iget-object v0, p0, La/g/a/a;->i:La/g/a/b;

    return-object v0
.end method

.method public getItem(I)Ljava/lang/Object;
    .locals 1

    iget-boolean v0, p0, La/g/a/a;->b:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, La/g/a/a;->d:Landroid/database/Cursor;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, Landroid/database/Cursor;->moveToPosition(I)Z

    iget-object p1, p0, La/g/a/a;->d:Landroid/database/Cursor;

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public getItemId(I)J
    .locals 3

    iget-boolean v0, p0, La/g/a/a;->b:Z

    const-wide/16 v1, 0x0

    if-eqz v0, :cond_0

    iget-object v0, p0, La/g/a/a;->d:Landroid/database/Cursor;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, Landroid/database/Cursor;->moveToPosition(I)Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object p1, p0, La/g/a/a;->d:Landroid/database/Cursor;

    iget v0, p0, La/g/a/a;->f:I

    invoke-interface {p1, v0}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v0

    return-wide v0

    :cond_0
    return-wide v1
.end method

.method public getView(ILandroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;
    .locals 1

    iget-boolean v0, p0, La/g/a/a;->b:Z

    if-eqz v0, :cond_2

    iget-object v0, p0, La/g/a/a;->d:Landroid/database/Cursor;

    invoke-interface {v0, p1}, Landroid/database/Cursor;->moveToPosition(I)Z

    move-result v0

    if-eqz v0, :cond_1

    if-nez p2, :cond_0

    iget-object p1, p0, La/g/a/a;->e:Landroid/content/Context;

    iget-object p2, p0, La/g/a/a;->d:Landroid/database/Cursor;

    invoke-virtual {p0, p1, p2, p3}, La/g/a/a;->d(Landroid/content/Context;Landroid/database/Cursor;Landroid/view/ViewGroup;)Landroid/view/View;

    move-result-object p2

    :cond_0
    iget-object p1, p0, La/g/a/a;->e:Landroid/content/Context;

    iget-object p3, p0, La/g/a/a;->d:Landroid/database/Cursor;

    invoke-virtual {p0, p2, p1, p3}, La/g/a/a;->a(Landroid/view/View;Landroid/content/Context;Landroid/database/Cursor;)V

    return-object p2

    :cond_1
    new-instance p2, Ljava/lang/IllegalStateException;

    new-instance p3, Ljava/lang/StringBuilder;

    invoke-direct {p3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v0, "couldn\'t move cursor to position "

    invoke-virtual {p3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "this should only be called when the cursor is valid"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
