.class public final enum La/j/d$a;
.super Ljava/lang/Enum;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/j/d;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "a"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "La/j/d$a;",
        ">;"
    }
.end annotation


# static fields
.field public static final synthetic $VALUES:[La/j/d$a;

.field public static final enum ON_ANY:La/j/d$a;

.field public static final enum ON_CREATE:La/j/d$a;

.field public static final enum ON_DESTROY:La/j/d$a;

.field public static final enum ON_PAUSE:La/j/d$a;

.field public static final enum ON_RESUME:La/j/d$a;

.field public static final enum ON_START:La/j/d$a;

.field public static final enum ON_STOP:La/j/d$a;


# direct methods
.method public static constructor <clinit>()V
    .locals 10

    new-instance v0, La/j/d$a;

    const-string v1, "ON_CREATE"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, La/j/d$a;-><init>(Ljava/lang/String;I)V

    sput-object v0, La/j/d$a;->ON_CREATE:La/j/d$a;

    new-instance v0, La/j/d$a;

    const-string v1, "ON_START"

    const/4 v3, 0x1

    invoke-direct {v0, v1, v3}, La/j/d$a;-><init>(Ljava/lang/String;I)V

    sput-object v0, La/j/d$a;->ON_START:La/j/d$a;

    new-instance v0, La/j/d$a;

    const-string v1, "ON_RESUME"

    const/4 v4, 0x2

    invoke-direct {v0, v1, v4}, La/j/d$a;-><init>(Ljava/lang/String;I)V

    sput-object v0, La/j/d$a;->ON_RESUME:La/j/d$a;

    new-instance v0, La/j/d$a;

    const-string v1, "ON_PAUSE"

    const/4 v5, 0x3

    invoke-direct {v0, v1, v5}, La/j/d$a;-><init>(Ljava/lang/String;I)V

    sput-object v0, La/j/d$a;->ON_PAUSE:La/j/d$a;

    new-instance v0, La/j/d$a;

    const-string v1, "ON_STOP"

    const/4 v6, 0x4

    invoke-direct {v0, v1, v6}, La/j/d$a;-><init>(Ljava/lang/String;I)V

    sput-object v0, La/j/d$a;->ON_STOP:La/j/d$a;

    new-instance v0, La/j/d$a;

    const-string v1, "ON_DESTROY"

    const/4 v7, 0x5

    invoke-direct {v0, v1, v7}, La/j/d$a;-><init>(Ljava/lang/String;I)V

    sput-object v0, La/j/d$a;->ON_DESTROY:La/j/d$a;

    new-instance v0, La/j/d$a;

    const-string v1, "ON_ANY"

    const/4 v8, 0x6

    invoke-direct {v0, v1, v8}, La/j/d$a;-><init>(Ljava/lang/String;I)V

    sput-object v0, La/j/d$a;->ON_ANY:La/j/d$a;

    const/4 v1, 0x7

    new-array v1, v1, [La/j/d$a;

    sget-object v9, La/j/d$a;->ON_CREATE:La/j/d$a;

    aput-object v9, v1, v2

    sget-object v2, La/j/d$a;->ON_START:La/j/d$a;

    aput-object v2, v1, v3

    sget-object v2, La/j/d$a;->ON_RESUME:La/j/d$a;

    aput-object v2, v1, v4

    sget-object v2, La/j/d$a;->ON_PAUSE:La/j/d$a;

    aput-object v2, v1, v5

    sget-object v2, La/j/d$a;->ON_STOP:La/j/d$a;

    aput-object v2, v1, v6

    sget-object v2, La/j/d$a;->ON_DESTROY:La/j/d$a;

    aput-object v2, v1, v7

    aput-object v0, v1, v8

    sput-object v1, La/j/d$a;->$VALUES:[La/j/d$a;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;I)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)La/j/d$a;
    .locals 1

    const-class v0, La/j/d$a;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, La/j/d$a;

    return-object p0
.end method

.method public static values()[La/j/d$a;
    .locals 1

    sget-object v0, La/j/d$a;->$VALUES:[La/j/d$a;

    invoke-virtual {v0}, [La/j/d$a;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [La/j/d$a;

    return-object v0
.end method
