package kotlin.coroutines;

import kotlin.Metadata;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
/* compiled from: CoroutineContext.kt */
@Metadata(d1 = {"\u0000\u0010\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0004H\n¢\u0006\u0002\b\u0005"}, d2 = {"<anonymous>", "Lkotlin/coroutines/CoroutineContext;", "acc", "element", "Lkotlin/coroutines/CoroutineContext$Element;", "invoke"}, k = 3, mv = {1, 6, 0}, xi = 48)
/* loaded from: classes.dex */
final class CoroutineContext$plus$1 extends Lambda implements Function2<CoroutineContext, CoroutineContext.Element, CoroutineContext> {
    public static final CoroutineContext$plus$1 INSTANCE = new CoroutineContext$plus$1();

    CoroutineContext$plus$1() {
        super(2);
    }

    @Override // kotlin.jvm.functions.Function2
    public final CoroutineContext invoke(CoroutineContext acc, CoroutineContext.Element element) {
        CoroutineContext left;
        Intrinsics.checkNotNullParameter(acc, "acc");
        Intrinsics.checkNotNullParameter(element, "element");
        CoroutineContext removed = acc.minusKey(element.getKey());
        if (removed == EmptyCoroutineContext.INSTANCE) {
            return element;
        }
        ContinuationInterceptor interceptor = (ContinuationInterceptor) removed.get(ContinuationInterceptor.Key);
        if (interceptor == null) {
            left = new CombinedContext(removed, element);
        } else {
            CoroutineContext left2 = removed.minusKey(ContinuationInterceptor.Key);
            left = left2 == EmptyCoroutineContext.INSTANCE ? new CombinedContext(element, interceptor) : new CombinedContext(new CombinedContext(left2, element), interceptor);
        }
        return left;
    }
}
