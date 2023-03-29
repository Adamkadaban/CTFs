package androidx.core.provider;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.provider.DocumentsContract;
import java.io.FileNotFoundException;
import java.util.List;
/* loaded from: classes.dex */
public final class DocumentsContractCompat {
    private static final String PATH_TREE = "tree";

    /* loaded from: classes.dex */
    public static final class DocumentCompat {
        public static final int FLAG_VIRTUAL_DOCUMENT = 512;

        private DocumentCompat() {
        }
    }

    public static boolean isDocumentUri(Context context, Uri uri) {
        if (Build.VERSION.SDK_INT >= 19) {
            return DocumentsContractApi19Impl.isDocumentUri(context, uri);
        }
        return false;
    }

    public static boolean isTreeUri(Uri uri) {
        if (Build.VERSION.SDK_INT < 21) {
            return false;
        }
        if (Build.VERSION.SDK_INT < 24) {
            List<String> paths = uri.getPathSegments();
            return paths.size() >= 2 && PATH_TREE.equals(paths.get(0));
        }
        return DocumentsContractApi24Impl.isTreeUri(uri);
    }

    public static String getDocumentId(Uri documentUri) {
        if (Build.VERSION.SDK_INT >= 19) {
            return DocumentsContractApi19Impl.getDocumentId(documentUri);
        }
        return null;
    }

    public static String getTreeDocumentId(Uri documentUri) {
        if (Build.VERSION.SDK_INT >= 21) {
            return DocumentsContractApi21Impl.getTreeDocumentId(documentUri);
        }
        return null;
    }

    public static Uri buildDocumentUri(String authority, String documentId) {
        if (Build.VERSION.SDK_INT >= 19) {
            return DocumentsContractApi19Impl.buildDocumentUri(authority, documentId);
        }
        return null;
    }

    public static Uri buildDocumentUriUsingTree(Uri treeUri, String documentId) {
        if (Build.VERSION.SDK_INT >= 21) {
            return DocumentsContractApi21Impl.buildDocumentUriUsingTree(treeUri, documentId);
        }
        return null;
    }

    public static Uri buildTreeDocumentUri(String authority, String documentId) {
        if (Build.VERSION.SDK_INT >= 21) {
            return DocumentsContractApi21Impl.buildTreeDocumentUri(authority, documentId);
        }
        return null;
    }

    public static Uri buildChildDocumentsUri(String authority, String parentDocumentId) {
        if (Build.VERSION.SDK_INT >= 21) {
            return DocumentsContractApi21Impl.buildChildDocumentsUri(authority, parentDocumentId);
        }
        return null;
    }

    public static Uri buildChildDocumentsUriUsingTree(Uri treeUri, String parentDocumentId) {
        if (Build.VERSION.SDK_INT >= 21) {
            return DocumentsContractApi21Impl.buildChildDocumentsUriUsingTree(treeUri, parentDocumentId);
        }
        return null;
    }

    public static Uri createDocument(ContentResolver content, Uri parentDocumentUri, String mimeType, String displayName) throws FileNotFoundException {
        if (Build.VERSION.SDK_INT >= 21) {
            return DocumentsContractApi21Impl.createDocument(content, parentDocumentUri, mimeType, displayName);
        }
        return null;
    }

    public static Uri renameDocument(ContentResolver content, Uri documentUri, String displayName) throws FileNotFoundException {
        if (Build.VERSION.SDK_INT >= 21) {
            return DocumentsContractApi21Impl.renameDocument(content, documentUri, displayName);
        }
        return null;
    }

    public static boolean removeDocument(ContentResolver content, Uri documentUri, Uri parentDocumentUri) throws FileNotFoundException {
        if (Build.VERSION.SDK_INT >= 24) {
            return DocumentsContractApi24Impl.removeDocument(content, documentUri, parentDocumentUri);
        }
        if (Build.VERSION.SDK_INT >= 19) {
            return DocumentsContractApi19Impl.deleteDocument(content, documentUri);
        }
        return false;
    }

    /* loaded from: classes.dex */
    private static class DocumentsContractApi19Impl {
        public static Uri buildDocumentUri(String authority, String documentId) {
            return DocumentsContract.buildDocumentUri(authority, documentId);
        }

        static boolean isDocumentUri(Context context, Uri uri) {
            return DocumentsContract.isDocumentUri(context, uri);
        }

        static String getDocumentId(Uri documentUri) {
            return DocumentsContract.getDocumentId(documentUri);
        }

        static boolean deleteDocument(ContentResolver content, Uri documentUri) throws FileNotFoundException {
            return DocumentsContract.deleteDocument(content, documentUri);
        }

        private DocumentsContractApi19Impl() {
        }
    }

    /* loaded from: classes.dex */
    private static class DocumentsContractApi21Impl {
        static String getTreeDocumentId(Uri documentUri) {
            return DocumentsContract.getTreeDocumentId(documentUri);
        }

        public static Uri buildTreeDocumentUri(String authority, String documentId) {
            return DocumentsContract.buildTreeDocumentUri(authority, documentId);
        }

        static Uri buildDocumentUriUsingTree(Uri treeUri, String documentId) {
            return DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId);
        }

        static Uri buildChildDocumentsUri(String authority, String parentDocumentId) {
            return DocumentsContract.buildChildDocumentsUri(authority, parentDocumentId);
        }

        static Uri buildChildDocumentsUriUsingTree(Uri treeUri, String parentDocumentId) {
            return DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentDocumentId);
        }

        static Uri createDocument(ContentResolver content, Uri parentDocumentUri, String mimeType, String displayName) throws FileNotFoundException {
            return DocumentsContract.createDocument(content, parentDocumentUri, mimeType, displayName);
        }

        static Uri renameDocument(ContentResolver content, Uri documentUri, String displayName) throws FileNotFoundException {
            return DocumentsContract.renameDocument(content, documentUri, displayName);
        }

        private DocumentsContractApi21Impl() {
        }
    }

    /* loaded from: classes.dex */
    private static class DocumentsContractApi24Impl {
        static boolean isTreeUri(Uri uri) {
            return DocumentsContract.isTreeUri(uri);
        }

        static boolean removeDocument(ContentResolver content, Uri documentUri, Uri parentDocumentUri) throws FileNotFoundException {
            return DocumentsContract.removeDocument(content, documentUri, parentDocumentUri);
        }

        private DocumentsContractApi24Impl() {
        }
    }

    private DocumentsContractCompat() {
    }
}
