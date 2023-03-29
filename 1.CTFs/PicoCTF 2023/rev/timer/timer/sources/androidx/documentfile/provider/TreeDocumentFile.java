package androidx.documentfile.provider;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.DocumentsContract;
import android.util.Log;
import java.util.ArrayList;
/* loaded from: classes.dex */
class TreeDocumentFile extends DocumentFile {
    private Context mContext;
    private Uri mUri;

    /* JADX INFO: Access modifiers changed from: package-private */
    public TreeDocumentFile(DocumentFile parent, Context context, Uri uri) {
        super(parent);
        this.mContext = context;
        this.mUri = uri;
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public DocumentFile createFile(String mimeType, String displayName) {
        Uri result = createFile(this.mContext, this.mUri, mimeType, displayName);
        if (result != null) {
            return new TreeDocumentFile(this, this.mContext, result);
        }
        return null;
    }

    private static Uri createFile(Context context, Uri self, String mimeType, String displayName) {
        try {
            return DocumentsContract.createDocument(context.getContentResolver(), self, mimeType, displayName);
        } catch (Exception e) {
            return null;
        }
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public DocumentFile createDirectory(String displayName) {
        Uri result = createFile(this.mContext, this.mUri, "vnd.android.document/directory", displayName);
        if (result != null) {
            return new TreeDocumentFile(this, this.mContext, result);
        }
        return null;
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public Uri getUri() {
        return this.mUri;
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public String getName() {
        return DocumentsContractApi19.getName(this.mContext, this.mUri);
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public String getType() {
        return DocumentsContractApi19.getType(this.mContext, this.mUri);
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public boolean isDirectory() {
        return DocumentsContractApi19.isDirectory(this.mContext, this.mUri);
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public boolean isFile() {
        return DocumentsContractApi19.isFile(this.mContext, this.mUri);
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public boolean isVirtual() {
        return DocumentsContractApi19.isVirtual(this.mContext, this.mUri);
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public long lastModified() {
        return DocumentsContractApi19.lastModified(this.mContext, this.mUri);
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public long length() {
        return DocumentsContractApi19.length(this.mContext, this.mUri);
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public boolean canRead() {
        return DocumentsContractApi19.canRead(this.mContext, this.mUri);
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public boolean canWrite() {
        return DocumentsContractApi19.canWrite(this.mContext, this.mUri);
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public boolean delete() {
        try {
            return DocumentsContract.deleteDocument(this.mContext.getContentResolver(), this.mUri);
        } catch (Exception e) {
            return false;
        }
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public boolean exists() {
        return DocumentsContractApi19.exists(this.mContext, this.mUri);
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public DocumentFile[] listFiles() {
        ContentResolver resolver = this.mContext.getContentResolver();
        Uri uri = this.mUri;
        Uri childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(uri, DocumentsContract.getDocumentId(uri));
        ArrayList<Uri> results = new ArrayList<>();
        Cursor c = null;
        try {
            try {
                c = resolver.query(childrenUri, new String[]{"document_id"}, null, null, null);
                while (c.moveToNext()) {
                    String documentId = c.getString(0);
                    Uri documentUri = DocumentsContract.buildDocumentUriUsingTree(this.mUri, documentId);
                    results.add(documentUri);
                }
            } catch (Exception e) {
                Log.w("DocumentFile", "Failed query: " + e);
            }
            Uri[] result = (Uri[]) results.toArray(new Uri[results.size()]);
            DocumentFile[] resultFiles = new DocumentFile[result.length];
            for (int i = 0; i < result.length; i++) {
                resultFiles[i] = new TreeDocumentFile(this, this.mContext, result[i]);
            }
            return resultFiles;
        } finally {
            closeQuietly(c);
        }
    }

    private static void closeQuietly(AutoCloseable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (RuntimeException rethrown) {
                throw rethrown;
            } catch (Exception e) {
            }
        }
    }

    @Override // androidx.documentfile.provider.DocumentFile
    public boolean renameTo(String displayName) {
        try {
            Uri result = DocumentsContract.renameDocument(this.mContext.getContentResolver(), this.mUri, displayName);
            if (result == null) {
                return false;
            }
            this.mUri = result;
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
