package androidx.emoji2.text;

import android.content.res.AssetManager;
import android.graphics.Typeface;
import android.util.SparseArray;
import androidx.core.os.TraceCompat;
import androidx.core.util.Preconditions;
import androidx.emoji2.text.flatbuffer.MetadataList;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
/* loaded from: classes.dex */
public final class MetadataRepo {
    private static final int DEFAULT_ROOT_SIZE = 1024;
    private static final String S_TRACE_CREATE_REPO = "EmojiCompat.MetadataRepo.create";
    private final char[] mEmojiCharArray;
    private final MetadataList mMetadataList;
    private final Node mRootNode = new Node(1024);
    private final Typeface mTypeface;

    private MetadataRepo(Typeface typeface, MetadataList metadataList) {
        this.mTypeface = typeface;
        this.mMetadataList = metadataList;
        this.mEmojiCharArray = new char[metadataList.listLength() * 2];
        constructIndex(metadataList);
    }

    public static MetadataRepo create(Typeface typeface) {
        try {
            TraceCompat.beginSection(S_TRACE_CREATE_REPO);
            return new MetadataRepo(typeface, new MetadataList());
        } finally {
            TraceCompat.endSection();
        }
    }

    public static MetadataRepo create(Typeface typeface, InputStream inputStream) throws IOException {
        try {
            TraceCompat.beginSection(S_TRACE_CREATE_REPO);
            return new MetadataRepo(typeface, MetadataListReader.read(inputStream));
        } finally {
            TraceCompat.endSection();
        }
    }

    public static MetadataRepo create(Typeface typeface, ByteBuffer byteBuffer) throws IOException {
        try {
            TraceCompat.beginSection(S_TRACE_CREATE_REPO);
            return new MetadataRepo(typeface, MetadataListReader.read(byteBuffer));
        } finally {
            TraceCompat.endSection();
        }
    }

    public static MetadataRepo create(AssetManager assetManager, String assetPath) throws IOException {
        try {
            TraceCompat.beginSection(S_TRACE_CREATE_REPO);
            Typeface typeface = Typeface.createFromAsset(assetManager, assetPath);
            return new MetadataRepo(typeface, MetadataListReader.read(assetManager, assetPath));
        } finally {
            TraceCompat.endSection();
        }
    }

    private void constructIndex(MetadataList metadataList) {
        int length = metadataList.listLength();
        for (int i = 0; i < length; i++) {
            EmojiMetadata metadata = new EmojiMetadata(this, i);
            Character.toChars(metadata.getId(), this.mEmojiCharArray, i * 2);
            put(metadata);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Typeface getTypeface() {
        return this.mTypeface;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getMetadataVersion() {
        return this.mMetadataList.version();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Node getRootNode() {
        return this.mRootNode;
    }

    public char[] getEmojiCharArray() {
        return this.mEmojiCharArray;
    }

    public MetadataList getMetadataList() {
        return this.mMetadataList;
    }

    void put(EmojiMetadata data) {
        Preconditions.checkNotNull(data, "emoji metadata cannot be null");
        Preconditions.checkArgument(data.getCodepointsLength() > 0, "invalid metadata codepoint length");
        this.mRootNode.put(data, 0, data.getCodepointsLength() - 1);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class Node {
        private final SparseArray<Node> mChildren;
        private EmojiMetadata mData;

        private Node() {
            this(1);
        }

        Node(int defaultChildrenSize) {
            this.mChildren = new SparseArray<>(defaultChildrenSize);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public Node get(int key) {
            SparseArray<Node> sparseArray = this.mChildren;
            if (sparseArray == null) {
                return null;
            }
            return sparseArray.get(key);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public final EmojiMetadata getData() {
            return this.mData;
        }

        void put(EmojiMetadata data, int start, int end) {
            Node node = get(data.getCodepointAt(start));
            if (node == null) {
                node = new Node();
                this.mChildren.put(data.getCodepointAt(start), node);
            }
            if (end > start) {
                node.put(data, start + 1, end);
            } else {
                node.mData = data;
            }
        }
    }
}
