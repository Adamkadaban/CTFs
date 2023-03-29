package androidx.core.view;

import android.view.View;
import android.view.ViewGroup;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.RestrictedSuspendLambda;
import kotlin.jvm.functions.Function2;
import kotlin.sequences.SequenceScope;
/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: ViewGroup.kt */
@Metadata(d1 = {"\u0000\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\u0010\u0000\u001a\u00020\u0001*\b\u0012\u0004\u0012\u00020\u00030\u0002H\u008a@"}, d2 = {"<anonymous>", "", "Lkotlin/sequences/SequenceScope;", "Landroid/view/View;"}, k = 3, mv = {1, 5, 1}, xi = 48)
@DebugMetadata(c = "androidx.core.view.ViewGroupKt$descendants$1", f = "ViewGroup.kt", i = {0, 0, 0, 1, 1}, l = {97, 99}, m = "invokeSuspend", n = {"$this$sequence", "$this$forEach$iv", "child", "$this$sequence", "$this$forEach$iv"}, s = {"L$0", "L$1", "L$2", "L$0", "L$1"})
/* loaded from: classes.dex */
public final class ViewGroupKt$descendants$1 extends RestrictedSuspendLambda implements Function2<SequenceScope<? super View>, Continuation<? super Unit>, Object> {
    final /* synthetic */ ViewGroup $this_descendants;
    int I$0;
    int I$1;
    private /* synthetic */ Object L$0;
    Object L$1;
    Object L$2;
    int label;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ViewGroupKt$descendants$1(ViewGroup viewGroup, Continuation<? super ViewGroupKt$descendants$1> continuation) {
        super(2, continuation);
        this.$this_descendants = viewGroup;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
        ViewGroupKt$descendants$1 viewGroupKt$descendants$1 = new ViewGroupKt$descendants$1(this.$this_descendants, continuation);
        viewGroupKt$descendants$1.L$0 = obj;
        return viewGroupKt$descendants$1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(SequenceScope<? super View> sequenceScope, Continuation<? super Unit> continuation) {
        return ((ViewGroupKt$descendants$1) create(sequenceScope, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    /* JADX WARN: Code restructure failed: missing block: B:10:0x004e, code lost:
        r7 = r5;
        r5 = r5 + 1;
        r9 = r3.getChildAt(r7);
        kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, "getChildAt(index)");
        r1.L$0 = r2;
        r1.L$1 = r3;
        r1.L$2 = r9;
        r1.I$0 = r5;
        r1.I$1 = r6;
        r1.label = 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:11:0x006c, code lost:
        if (r2.yield(r9, r1) != r0) goto L12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x006e, code lost:
        return r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x006f, code lost:
        r8 = r2;
        r2 = r4;
        r4 = r6;
        r6 = r9;
        r7 = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x00a0, code lost:
        if (r5 >= r6) goto L20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x00a5, code lost:
        return kotlin.Unit.INSTANCE;
     */
    /* JADX WARN: Code restructure failed: missing block: B:9:0x004c, code lost:
        if (r6 > 0) goto L9;
     */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:19:0x0095 -> B:20:0x0097). Please submit an issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:21:0x009c -> B:22:0x00a0). Please submit an issue!!! */
    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r12) {
        /*
            r11 = this;
            java.lang.Object r0 = kotlin.coroutines.intrinsics.IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r1 = r11.label
            switch(r1) {
                case 0: goto L3c;
                case 1: goto L25;
                case 2: goto L11;
                default: goto L9;
            }
        L9:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r0)
            throw r12
        L11:
            r1 = r11
            r2 = 0
            r3 = 0
            int r4 = r1.I$1
            int r5 = r1.I$0
            java.lang.Object r6 = r1.L$1
            android.view.ViewGroup r6 = (android.view.ViewGroup) r6
            java.lang.Object r7 = r1.L$0
            kotlin.sequences.SequenceScope r7 = (kotlin.sequences.SequenceScope) r7
            kotlin.ResultKt.throwOnFailure(r12)
            goto L97
        L25:
            r1 = r11
            r2 = 0
            r3 = 0
            int r4 = r1.I$1
            int r5 = r1.I$0
            java.lang.Object r6 = r1.L$2
            android.view.View r6 = (android.view.View) r6
            java.lang.Object r7 = r1.L$1
            android.view.ViewGroup r7 = (android.view.ViewGroup) r7
            java.lang.Object r8 = r1.L$0
            kotlin.sequences.SequenceScope r8 = (kotlin.sequences.SequenceScope) r8
            kotlin.ResultKt.throwOnFailure(r12)
            goto L75
        L3c:
            kotlin.ResultKt.throwOnFailure(r12)
            r1 = r11
            java.lang.Object r2 = r1.L$0
            kotlin.sequences.SequenceScope r2 = (kotlin.sequences.SequenceScope) r2
            android.view.ViewGroup r3 = r1.$this_descendants
            r4 = 0
            r5 = 0
            int r6 = r3.getChildCount()
            if (r6 <= 0) goto La2
        L4e:
            r7 = r5
            r8 = 1
            int r5 = r5 + r8
            android.view.View r9 = r3.getChildAt(r7)
            java.lang.String r7 = "getChildAt(index)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, r7)
            r7 = r9
            r9 = 0
            r1.L$0 = r2
            r1.L$1 = r3
            r1.L$2 = r7
            r1.I$0 = r5
            r1.I$1 = r6
            r1.label = r8
            java.lang.Object r8 = r2.yield(r7, r1)
            if (r8 != r0) goto L6f
            return r0
        L6f:
            r8 = r2
            r2 = r4
            r4 = r6
            r6 = r7
            r7 = r3
            r3 = r9
        L75:
            boolean r9 = r6 instanceof android.view.ViewGroup
            if (r9 == 0) goto L9c
            r9 = r6
            android.view.ViewGroup r9 = (android.view.ViewGroup) r9
            kotlin.sequences.Sequence r9 = androidx.core.view.ViewGroupKt.getDescendants(r9)
            r1.L$0 = r8
            r1.L$1 = r7
            r10 = 0
            r1.L$2 = r10
            r1.I$0 = r5
            r1.I$1 = r4
            r10 = 2
            r1.label = r10
            java.lang.Object r6 = r8.yieldAll(r9, r1)
            if (r6 != r0) goto L95
            return r0
        L95:
            r6 = r7
            r7 = r8
        L97:
            r3 = r6
            r6 = r4
            r4 = r2
            r2 = r7
            goto La0
        L9c:
            r6 = r4
            r3 = r7
            r4 = r2
            r2 = r8
        La0:
            if (r5 < r6) goto L4e
        La2:
        La3:
            kotlin.Unit r0 = kotlin.Unit.INSTANCE
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.view.ViewGroupKt$descendants$1.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
