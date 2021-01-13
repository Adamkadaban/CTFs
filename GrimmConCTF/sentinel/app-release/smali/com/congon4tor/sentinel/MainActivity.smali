.class public Lcom/congon4tor/sentinel/MainActivity;
.super La/b/k/e;
.source ""


# instance fields
.field public p:Landroid/widget/TextView;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, La/b/k/e;-><init>()V

    return-void
.end method


# virtual methods
.method public onCreate(Landroid/os/Bundle;)V
    .locals 3

    invoke-super {p0, p1}, La/b/k/e;->onCreate(Landroid/os/Bundle;)V

    const p1, 0x7f0a001c

    invoke-virtual {p0, p1}, La/b/k/e;->setContentView(I)V

    const p1, 0x7f0c001c

    invoke-virtual {p0, p1}, Landroid/app/Activity;->getString(I)Ljava/lang/String;

    move-result-object p1

    const v0, 0x7f070079

    invoke-virtual {p0, v0}, La/b/k/e;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/TextView;

    iput-object v0, p0, Lcom/congon4tor/sentinel/MainActivity;->p:Landroid/widget/TextView;

    const v0, 0x7f0700aa

    invoke-virtual {p0, v0}, La/b/k/e;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/EditText;

    const v1, 0x7f0700dc

    invoke-virtual {p0, v1}, La/b/k/e;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/widget/Button;

    new-instance v2, Lcom/congon4tor/sentinel/MainActivity$a;

    invoke-direct {v2, p0, p1, v0}, Lcom/congon4tor/sentinel/MainActivity$a;-><init>(Lcom/congon4tor/sentinel/MainActivity;Ljava/lang/String;Landroid/widget/EditText;)V

    invoke-virtual {v1, v2}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    return-void
.end method
