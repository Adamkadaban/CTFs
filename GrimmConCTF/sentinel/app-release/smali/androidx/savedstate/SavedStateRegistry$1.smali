.class public Landroidx/savedstate/SavedStateRegistry$1;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements La/j/e;


# instance fields
.field public final synthetic a:La/l/a;


# direct methods
.method public constructor <init>(La/l/a;)V
    .locals 0

    iput-object p1, p0, Landroidx/savedstate/SavedStateRegistry$1;->a:La/l/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public g(La/j/g;La/j/d$a;)V
    .locals 0

    sget-object p1, La/j/d$a;->ON_START:La/j/d$a;

    if-ne p2, p1, :cond_0

    iget-object p1, p0, Landroidx/savedstate/SavedStateRegistry$1;->a:La/l/a;

    const/4 p2, 0x1

    goto :goto_0

    :cond_0
    sget-object p1, La/j/d$a;->ON_STOP:La/j/d$a;

    if-ne p2, p1, :cond_1

    iget-object p1, p0, Landroidx/savedstate/SavedStateRegistry$1;->a:La/l/a;

    const/4 p2, 0x0

    :goto_0
    iput-boolean p2, p1, La/l/a;->d:Z

    :cond_1
    return-void
.end method
