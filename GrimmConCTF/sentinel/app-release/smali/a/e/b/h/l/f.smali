.class public La/e/b/h/l/f;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements La/e/b/h/l/d;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/e/b/h/l/f$a;
    }
.end annotation


# instance fields
.field public a:La/e/b/h/l/d;

.field public b:Z

.field public c:Z

.field public d:La/e/b/h/l/o;

.field public e:La/e/b/h/l/f$a;

.field public f:I

.field public g:I

.field public h:I

.field public i:La/e/b/h/l/g;

.field public j:Z

.field public k:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "La/e/b/h/l/d;",
            ">;"
        }
    .end annotation
.end field

.field public l:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "La/e/b/h/l/f;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(La/e/b/h/l/o;)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-object v0, p0, La/e/b/h/l/f;->a:La/e/b/h/l/d;

    const/4 v1, 0x0

    iput-boolean v1, p0, La/e/b/h/l/f;->b:Z

    iput-boolean v1, p0, La/e/b/h/l/f;->c:Z

    sget-object v2, La/e/b/h/l/f$a;->b:La/e/b/h/l/f$a;

    iput-object v2, p0, La/e/b/h/l/f;->e:La/e/b/h/l/f$a;

    const/4 v2, 0x1

    iput v2, p0, La/e/b/h/l/f;->h:I

    iput-object v0, p0, La/e/b/h/l/f;->i:La/e/b/h/l/g;

    iput-boolean v1, p0, La/e/b/h/l/f;->j:Z

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, La/e/b/h/l/f;->k:Ljava/util/List;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, La/e/b/h/l/f;->l:Ljava/util/List;

    iput-object p1, p0, La/e/b/h/l/f;->d:La/e/b/h/l/o;

    return-void
.end method


# virtual methods
.method public a(La/e/b/h/l/d;)V
    .locals 5

    iget-object p1, p0, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/l/f;

    iget-boolean v0, v0, La/e/b/h/l/f;->j:Z

    if-nez v0, :cond_0

    return-void

    :cond_1
    const/4 p1, 0x1

    iput-boolean p1, p0, La/e/b/h/l/f;->c:Z

    iget-object v0, p0, La/e/b/h/l/f;->a:La/e/b/h/l/d;

    if-eqz v0, :cond_2

    invoke-interface {v0, p0}, La/e/b/h/l/d;->a(La/e/b/h/l/d;)V

    :cond_2
    iget-boolean v0, p0, La/e/b/h/l/f;->b:Z

    if-eqz v0, :cond_3

    iget-object p1, p0, La/e/b/h/l/f;->d:La/e/b/h/l/o;

    invoke-virtual {p1, p0}, La/e/b/h/l/o;->a(La/e/b/h/l/d;)V

    return-void

    :cond_3
    const/4 v0, 0x0

    const/4 v1, 0x0

    iget-object v2, p0, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_5

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/l/f;

    instance-of v4, v3, La/e/b/h/l/g;

    if-eqz v4, :cond_4

    goto :goto_0

    :cond_4
    add-int/lit8 v1, v1, 0x1

    move-object v0, v3

    goto :goto_0

    :cond_5
    if-eqz v0, :cond_8

    if-ne v1, p1, :cond_8

    iget-boolean p1, v0, La/e/b/h/l/f;->j:Z

    if-eqz p1, :cond_8

    iget-object p1, p0, La/e/b/h/l/f;->i:La/e/b/h/l/g;

    if-eqz p1, :cond_7

    iget-boolean v1, p1, La/e/b/h/l/f;->j:Z

    if-eqz v1, :cond_6

    iget v1, p0, La/e/b/h/l/f;->h:I

    iget p1, p1, La/e/b/h/l/f;->g:I

    mul-int/2addr v1, p1

    iput v1, p0, La/e/b/h/l/f;->f:I

    goto :goto_1

    :cond_6
    return-void

    :cond_7
    :goto_1
    iget p1, v0, La/e/b/h/l/f;->g:I

    iget v0, p0, La/e/b/h/l/f;->f:I

    add-int/2addr p1, v0

    invoke-virtual {p0, p1}, La/e/b/h/l/f;->c(I)V

    :cond_8
    iget-object p1, p0, La/e/b/h/l/f;->a:La/e/b/h/l/d;

    if-eqz p1, :cond_9

    invoke-interface {p1, p0}, La/e/b/h/l/d;->a(La/e/b/h/l/d;)V

    :cond_9
    return-void
.end method

.method public b()V
    .locals 1

    iget-object v0, p0, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->clear()V

    iget-object v0, p0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->clear()V

    const/4 v0, 0x0

    iput-boolean v0, p0, La/e/b/h/l/f;->j:Z

    iput v0, p0, La/e/b/h/l/f;->g:I

    iput-boolean v0, p0, La/e/b/h/l/f;->c:Z

    iput-boolean v0, p0, La/e/b/h/l/f;->b:Z

    return-void
.end method

.method public c(I)V
    .locals 1

    iget-boolean v0, p0, La/e/b/h/l/f;->j:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    const/4 v0, 0x1

    iput-boolean v0, p0, La/e/b/h/l/f;->j:Z

    iput p1, p0, La/e/b/h/l/f;->g:I

    iget-object p1, p0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/l/d;

    invoke-interface {v0, v0}, La/e/b/h/l/d;->a(La/e/b/h/l/d;)V

    goto :goto_0

    :cond_1
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, La/e/b/h/l/f;->d:La/e/b/h/l/o;

    iget-object v1, v1, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 1
    iget-object v1, v1, La/e/b/h/d;->f0:Ljava/lang/String;

    .line 2
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ":"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, La/e/b/h/l/f;->e:La/e/b/h/l/f$a;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "("

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-boolean v1, p0, La/e/b/h/l/f;->j:Z

    if-eqz v1, :cond_0

    iget v1, p0, La/e/b/h/l/f;->g:I

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    goto :goto_0

    :cond_0
    const-string v1, "unresolved"

    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ") <t="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ":d="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ">"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
