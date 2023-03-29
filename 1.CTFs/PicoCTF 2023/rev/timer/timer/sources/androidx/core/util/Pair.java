package androidx.core.util;
/* loaded from: classes.dex */
public class Pair<F, S> {
    public final F first;
    public final S second;

    public Pair(F first, S second) {
        this.first = first;
        this.second = second;
    }

    public boolean equals(Object o) {
        if (o instanceof Pair) {
            Pair<?, ?> p = (Pair) o;
            return ObjectsCompat.equals(p.first, this.first) && ObjectsCompat.equals(p.second, this.second);
        }
        return false;
    }

    public int hashCode() {
        F f = this.first;
        int hashCode = f == null ? 0 : f.hashCode();
        S s = this.second;
        return hashCode ^ (s != null ? s.hashCode() : 0);
    }

    public String toString() {
        return "Pair{" + this.first + " " + this.second + "}";
    }

    public static <A, B> Pair<A, B> create(A a, B b) {
        return new Pair<>(a, b);
    }
}
