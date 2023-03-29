package androidx.core.net;
/* loaded from: classes.dex */
public class ParseException extends RuntimeException {
    public final String response;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ParseException(String response) {
        super(response);
        this.response = response;
    }
}
