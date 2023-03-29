package kotlin.sequences;

import kotlin.Metadata;
import kotlin.collections.IndexedValue;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
/* compiled from: _Sequences.kt */
@Metadata(d1 = {"\u0000\u0012\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u00022\f\u0010\u0003\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0004H\n¢\u0006\u0004\b\u0005\u0010\u0006"}, d2 = {"<anonymous>", "", "T", "it", "Lkotlin/collections/IndexedValue;", "invoke", "(Lkotlin/collections/IndexedValue;)Ljava/lang/Boolean;"}, k = 3, mv = {1, 6, 0}, xi = 48)
/* loaded from: classes.dex */
final class SequencesKt___SequencesKt$filterIndexed$1 extends Lambda implements Function1<IndexedValue<? extends T>, Boolean> {
    final /* synthetic */ Function2<Integer, T, Boolean> $predicate;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public SequencesKt___SequencesKt$filterIndexed$1(Function2<? super Integer, ? super T, Boolean> function2) {
        super(1);
        this.$predicate = function2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Boolean invoke(IndexedValue<? extends T> it) {
        Intrinsics.checkNotNullParameter(it, "it");
        return this.$predicate.invoke(Integer.valueOf(it.getIndex()), it.getValue());
    }
}
