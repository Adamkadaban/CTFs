.class public Lcom/congon4tor/sentinel/MainActivity$a;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements Landroid/view/View$OnClickListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/congon4tor/sentinel/MainActivity;->onCreate(Landroid/os/Bundle;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic b:Ljava/lang/String;

.field public final synthetic c:Landroid/widget/EditText;

.field public final synthetic d:Lcom/congon4tor/sentinel/MainActivity;


# direct methods
.method public constructor <init>(Lcom/congon4tor/sentinel/MainActivity;Ljava/lang/String;Landroid/widget/EditText;)V
    .locals 0

    iput-object p1, p0, Lcom/congon4tor/sentinel/MainActivity$a;->d:Lcom/congon4tor/sentinel/MainActivity;

    iput-object p2, p0, Lcom/congon4tor/sentinel/MainActivity$a;->b:Ljava/lang/String;

    iput-object p3, p0, Lcom/congon4tor/sentinel/MainActivity$a;->c:Landroid/widget/EditText;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onClick(Landroid/view/View;)V
    .locals 4

    const/4 p1, 0x2

    new-array p1, p1, [Ljava/lang/String;

    iget-object v0, p0, Lcom/congon4tor/sentinel/MainActivity$a;->b:Ljava/lang/String;

    const/4 v1, 0x0

    aput-object v0, p1, v1

    iget-object v0, p0, Lcom/congon4tor/sentinel/MainActivity$a;->c:Landroid/widget/EditText;

    invoke-virtual {v0}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    const/4 v2, 0x1

    aput-object v0, p1, v2

    new-instance v0, Lb/b/a/a/a;

    iget-object v3, p0, Lcom/congon4tor/sentinel/MainActivity$a;->d:Lcom/congon4tor/sentinel/MainActivity;

    invoke-direct {v0, v3}, Lb/b/a/a/a;-><init>(Lcom/congon4tor/sentinel/MainActivity;)V

    new-array v2, v2, [[Ljava/lang/String;

    aput-object p1, v2, v1

    invoke-virtual {v0, v2}, Landroid/os/AsyncTask;->execute([Ljava/lang/Object;)Landroid/os/AsyncTask;

    return-void
.end method
