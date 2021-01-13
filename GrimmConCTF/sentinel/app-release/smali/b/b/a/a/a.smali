.class public Lb/b/a/a/a;
.super Landroid/os/AsyncTask;
.source ""


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Landroid/os/AsyncTask<",
        "[",
        "Ljava/lang/String;",
        "Ljava/lang/Integer;",
        "Ljava/lang/String;",
        ">;"
    }
.end annotation


# instance fields
.field public a:Lcom/congon4tor/sentinel/MainActivity;


# direct methods
.method public constructor <init>(Lcom/congon4tor/sentinel/MainActivity;)V
    .locals 0

    invoke-direct {p0}, Landroid/os/AsyncTask;-><init>()V

    iput-object p1, p0, Lb/b/a/a/a;->a:Lcom/congon4tor/sentinel/MainActivity;

    return-void
.end method


# virtual methods
.method public doInBackground([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, [[Ljava/lang/String;

    const/4 v0, 0x0

    .line 1
    aget-object v1, p1, v0

    aget-object v1, v1, v0

    aget-object p1, p1, v0

    const/4 v2, 0x1

    aget-object p1, p1, v2

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v2

    const/4 v3, 0x5

    if-eq v2, v3, :cond_0

    const-string p1, "Invalid password length"

    goto :goto_1

    :cond_0
    new-instance v2, Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/String;->getBytes()[B

    move-result-object v1

    invoke-static {v1, v0}, Landroid/util/Base64;->decode([BI)[B

    move-result-object v1

    invoke-virtual {p1}, Ljava/lang/String;->getBytes()[B

    move-result-object p1

    .line 2
    array-length v3, v1

    new-array v3, v3, [B

    :goto_0
    array-length v4, v1

    if-ge v0, v4, :cond_1

    aget-byte v4, v1, v0

    array-length v5, p1

    rem-int v5, v0, v5

    aget-byte v5, p1, v5

    xor-int/2addr v4, v5

    int-to-byte v4, v4

    aput-byte v4, v3, v0

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    .line 3
    :cond_1
    invoke-direct {v2, v3}, Ljava/lang/String;-><init>([B)V

    move-object p1, v2

    :goto_1
    return-object p1
.end method

.method public onPostExecute(Ljava/lang/Object;)V
    .locals 1

    check-cast p1, Ljava/lang/String;

    .line 1
    invoke-super {p0, p1}, Landroid/os/AsyncTask;->onPostExecute(Ljava/lang/Object;)V

    iget-object v0, p0, Lb/b/a/a/a;->a:Lcom/congon4tor/sentinel/MainActivity;

    .line 2
    iget-object v0, v0, Lcom/congon4tor/sentinel/MainActivity;->p:Landroid/widget/TextView;

    invoke-virtual {v0, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    return-void
.end method
