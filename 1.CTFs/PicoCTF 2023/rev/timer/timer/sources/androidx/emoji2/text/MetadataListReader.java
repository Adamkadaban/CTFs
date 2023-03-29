package androidx.emoji2.text;

import android.content.res.AssetManager;
import androidx.emoji2.text.flatbuffer.MetadataList;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class MetadataListReader {
    private static final int EMJI_TAG = 1164798569;
    private static final int EMJI_TAG_DEPRECATED = 1701669481;
    private static final int META_TABLE_NAME = 1835365473;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public interface OpenTypeReader {
        public static final int UINT16_BYTE_COUNT = 2;
        public static final int UINT32_BYTE_COUNT = 4;

        long getPosition();

        int readTag() throws IOException;

        long readUnsignedInt() throws IOException;

        int readUnsignedShort() throws IOException;

        void skip(int i) throws IOException;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static MetadataList read(InputStream inputStream) throws IOException {
        OpenTypeReader openTypeReader = new InputStreamOpenTypeReader(inputStream);
        OffsetInfo offsetInfo = findOffsetInfo(openTypeReader);
        openTypeReader.skip((int) (offsetInfo.getStartOffset() - openTypeReader.getPosition()));
        ByteBuffer buffer = ByteBuffer.allocate((int) offsetInfo.getLength());
        int numRead = inputStream.read(buffer.array());
        if (numRead != offsetInfo.getLength()) {
            throw new IOException("Needed " + offsetInfo.getLength() + " bytes, got " + numRead);
        }
        return MetadataList.getRootAsMetadataList(buffer);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static MetadataList read(ByteBuffer byteBuffer) throws IOException {
        ByteBuffer newBuffer = byteBuffer.duplicate();
        OpenTypeReader reader = new ByteBufferReader(newBuffer);
        OffsetInfo offsetInfo = findOffsetInfo(reader);
        newBuffer.position((int) offsetInfo.getStartOffset());
        return MetadataList.getRootAsMetadataList(newBuffer);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static MetadataList read(AssetManager assetManager, String assetPath) throws IOException {
        InputStream inputStream = assetManager.open(assetPath);
        try {
            MetadataList read = read(inputStream);
            if (inputStream != null) {
                inputStream.close();
            }
            return read;
        } catch (Throwable th) {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (Throwable th2) {
                    th.addSuppressed(th2);
                }
            }
            throw th;
        }
    }

    private static OffsetInfo findOffsetInfo(OpenTypeReader reader) throws IOException {
        reader.skip(4);
        int tableCount = reader.readUnsignedShort();
        if (tableCount > 100) {
            throw new IOException("Cannot read metadata.");
        }
        reader.skip(6);
        long metaOffset = -1;
        int i = 0;
        while (true) {
            if (i >= tableCount) {
                break;
            }
            int tag = reader.readTag();
            reader.skip(4);
            long offset = reader.readUnsignedInt();
            reader.skip(4);
            if (META_TABLE_NAME != tag) {
                i++;
            } else {
                metaOffset = offset;
                break;
            }
        }
        if (metaOffset != -1) {
            reader.skip((int) (metaOffset - reader.getPosition()));
            reader.skip(12);
            long mapsCount = reader.readUnsignedInt();
            for (int i2 = 0; i2 < mapsCount; i2++) {
                int tag2 = reader.readTag();
                long dataOffset = reader.readUnsignedInt();
                long dataLength = reader.readUnsignedInt();
                if (EMJI_TAG == tag2 || EMJI_TAG_DEPRECATED == tag2) {
                    return new OffsetInfo(dataOffset + metaOffset, dataLength);
                }
            }
        }
        throw new IOException("Cannot read metadata.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class OffsetInfo {
        private final long mLength;
        private final long mStartOffset;

        OffsetInfo(long startOffset, long length) {
            this.mStartOffset = startOffset;
            this.mLength = length;
        }

        long getStartOffset() {
            return this.mStartOffset;
        }

        long getLength() {
            return this.mLength;
        }
    }

    static int toUnsignedShort(short value) {
        return 65535 & value;
    }

    static long toUnsignedInt(int value) {
        return value & 4294967295L;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class InputStreamOpenTypeReader implements OpenTypeReader {
        private final byte[] mByteArray;
        private final ByteBuffer mByteBuffer;
        private final InputStream mInputStream;
        private long mPosition = 0;

        InputStreamOpenTypeReader(InputStream inputStream) {
            this.mInputStream = inputStream;
            byte[] bArr = new byte[4];
            this.mByteArray = bArr;
            ByteBuffer wrap = ByteBuffer.wrap(bArr);
            this.mByteBuffer = wrap;
            wrap.order(ByteOrder.BIG_ENDIAN);
        }

        @Override // androidx.emoji2.text.MetadataListReader.OpenTypeReader
        public int readUnsignedShort() throws IOException {
            this.mByteBuffer.position(0);
            read(2);
            return MetadataListReader.toUnsignedShort(this.mByteBuffer.getShort());
        }

        @Override // androidx.emoji2.text.MetadataListReader.OpenTypeReader
        public long readUnsignedInt() throws IOException {
            this.mByteBuffer.position(0);
            read(4);
            return MetadataListReader.toUnsignedInt(this.mByteBuffer.getInt());
        }

        @Override // androidx.emoji2.text.MetadataListReader.OpenTypeReader
        public int readTag() throws IOException {
            this.mByteBuffer.position(0);
            read(4);
            return this.mByteBuffer.getInt();
        }

        @Override // androidx.emoji2.text.MetadataListReader.OpenTypeReader
        public void skip(int numOfBytes) throws IOException {
            while (numOfBytes > 0) {
                int skipped = (int) this.mInputStream.skip(numOfBytes);
                if (skipped < 1) {
                    throw new IOException("Skip didn't move at least 1 byte forward");
                }
                numOfBytes -= skipped;
                this.mPosition += skipped;
            }
        }

        @Override // androidx.emoji2.text.MetadataListReader.OpenTypeReader
        public long getPosition() {
            return this.mPosition;
        }

        private void read(int numOfBytes) throws IOException {
            if (this.mInputStream.read(this.mByteArray, 0, numOfBytes) != numOfBytes) {
                throw new IOException("read failed");
            }
            this.mPosition += numOfBytes;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class ByteBufferReader implements OpenTypeReader {
        private final ByteBuffer mByteBuffer;

        ByteBufferReader(ByteBuffer byteBuffer) {
            this.mByteBuffer = byteBuffer;
            byteBuffer.order(ByteOrder.BIG_ENDIAN);
        }

        @Override // androidx.emoji2.text.MetadataListReader.OpenTypeReader
        public int readUnsignedShort() throws IOException {
            return MetadataListReader.toUnsignedShort(this.mByteBuffer.getShort());
        }

        @Override // androidx.emoji2.text.MetadataListReader.OpenTypeReader
        public long readUnsignedInt() throws IOException {
            return MetadataListReader.toUnsignedInt(this.mByteBuffer.getInt());
        }

        @Override // androidx.emoji2.text.MetadataListReader.OpenTypeReader
        public int readTag() throws IOException {
            return this.mByteBuffer.getInt();
        }

        @Override // androidx.emoji2.text.MetadataListReader.OpenTypeReader
        public void skip(int numOfBytes) throws IOException {
            ByteBuffer byteBuffer = this.mByteBuffer;
            byteBuffer.position(byteBuffer.position() + numOfBytes);
        }

        @Override // androidx.emoji2.text.MetadataListReader.OpenTypeReader
        public long getPosition() {
            return this.mByteBuffer.position();
        }
    }

    private MetadataListReader() {
    }
}
