package com.google.android.material.color;

import android.content.Context;
import android.util.Pair;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.UByte;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public final class ColorResourcesTableCreator {
    private static final byte ANDROID_PACKAGE_ID = 1;
    private static final byte APPLICATION_PACKAGE_ID = Byte.MAX_VALUE;
    private static final short HEADER_TYPE_PACKAGE = 512;
    private static final short HEADER_TYPE_RES_TABLE = 2;
    private static final short HEADER_TYPE_STRING_POOL = 1;
    private static final short HEADER_TYPE_TYPE = 513;
    private static final short HEADER_TYPE_TYPE_SPEC = 514;
    private static final String RESOURCE_TYPE_NAME_COLOR = "color";
    private static byte typeIdColor;
    private static final PackageInfo ANDROID_PACKAGE_INFO = new PackageInfo(1, "android");
    private static final Comparator<ColorResource> COLOR_RESOURCE_COMPARATOR = new Comparator<ColorResource>() { // from class: com.google.android.material.color.ColorResourcesTableCreator.1
        @Override // java.util.Comparator
        public int compare(ColorResource res1, ColorResource res2) {
            return res1.entryId - res2.entryId;
        }
    };

    private ColorResourcesTableCreator() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] create(Context context, Map<Integer, Integer> colorMapping) throws IOException {
        PackageInfo packageInfo;
        if (colorMapping.entrySet().isEmpty()) {
            throw new IllegalArgumentException("No color resources provided for harmonization.");
        }
        PackageInfo applicationPackageInfo = new PackageInfo(127, context.getPackageName());
        Map<PackageInfo, List<ColorResource>> colorResourceMap = new HashMap<>();
        ColorResource colorResource = null;
        for (Map.Entry<Integer, Integer> entry : colorMapping.entrySet()) {
            colorResource = new ColorResource(entry.getKey().intValue(), context.getResources().getResourceName(entry.getKey().intValue()), entry.getValue().intValue());
            if (!context.getResources().getResourceTypeName(entry.getKey().intValue()).equals("color")) {
                throw new IllegalArgumentException("Non color resource found: name=" + colorResource.name + ", typeId=" + Integer.toHexString(colorResource.typeId & UByte.MAX_VALUE));
            }
            if (colorResource.packageId == 1) {
                packageInfo = ANDROID_PACKAGE_INFO;
            } else if (colorResource.packageId == Byte.MAX_VALUE) {
                packageInfo = applicationPackageInfo;
            } else {
                throw new IllegalArgumentException("Not supported with unknown package id: " + ((int) colorResource.packageId));
            }
            if (!colorResourceMap.containsKey(packageInfo)) {
                colorResourceMap.put(packageInfo, new ArrayList<>());
            }
            colorResourceMap.get(packageInfo).add(colorResource);
        }
        byte b = colorResource.typeId;
        typeIdColor = b;
        if (b == 0) {
            throw new IllegalArgumentException("No color resources found for harmonization.");
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        new ResTable(colorResourceMap).writeTo(outputStream);
        return outputStream.toByteArray();
    }

    /* loaded from: classes.dex */
    private static class ResTable {
        private static final short HEADER_SIZE = 12;
        private final ResChunkHeader header;
        private final int packageCount;
        private final List<PackageChunk> packageChunks = new ArrayList();
        private final StringPoolChunk stringPool = new StringPoolChunk(new String[0]);

        ResTable(Map<PackageInfo, List<ColorResource>> colorResourceMap) {
            this.packageCount = colorResourceMap.size();
            for (Map.Entry<PackageInfo, List<ColorResource>> entry : colorResourceMap.entrySet()) {
                List<ColorResource> colorResources = entry.getValue();
                Collections.sort(colorResources, ColorResourcesTableCreator.COLOR_RESOURCE_COMPARATOR);
                this.packageChunks.add(new PackageChunk(entry.getKey(), colorResources));
            }
            this.header = new ResChunkHeader(ColorResourcesTableCreator.HEADER_TYPE_RES_TABLE, HEADER_SIZE, getOverallSize());
        }

        void writeTo(ByteArrayOutputStream outputStream) throws IOException {
            this.header.writeTo(outputStream);
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.packageCount));
            this.stringPool.writeTo(outputStream);
            for (PackageChunk packageChunk : this.packageChunks) {
                packageChunk.writeTo(outputStream);
            }
        }

        private int getOverallSize() {
            int packageChunkSize = 0;
            for (PackageChunk packageChunk : this.packageChunks) {
                packageChunkSize += packageChunk.getChunkSize();
            }
            return this.stringPool.getChunkSize() + 12 + packageChunkSize;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class ResChunkHeader {
        private final int chunkSize;
        private final short headerSize;
        private final short type;

        ResChunkHeader(short type, short headerSize, int chunkSize) {
            this.type = type;
            this.headerSize = headerSize;
            this.chunkSize = chunkSize;
        }

        void writeTo(ByteArrayOutputStream outputStream) throws IOException {
            outputStream.write(ColorResourcesTableCreator.shortToByteArray(this.type));
            outputStream.write(ColorResourcesTableCreator.shortToByteArray(this.headerSize));
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.chunkSize));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class StringPoolChunk {
        private static final int FLAG_UTF8 = 256;
        private static final short HEADER_SIZE = 28;
        private static final int STYLED_SPAN_LIST_END = -1;
        private final int chunkSize;
        private final ResChunkHeader header;
        private final int stringCount;
        private final List<Integer> stringIndex;
        private final List<byte[]> strings;
        private final int stringsPaddingSize;
        private final int stringsStart;
        private final int styledSpanCount;
        private final List<Integer> styledSpanIndex;
        private final List<List<StringStyledSpan>> styledSpans;
        private final int styledSpansStart;
        private final boolean utf8Encode;

        StringPoolChunk(String... rawStrings) {
            this(false, rawStrings);
        }

        /* JADX WARN: Multi-variable type inference failed */
        StringPoolChunk(boolean utf8, String... rawStrings) {
            this.stringIndex = new ArrayList();
            this.styledSpanIndex = new ArrayList();
            this.strings = new ArrayList();
            this.styledSpans = new ArrayList();
            this.utf8Encode = utf8;
            int stringOffset = 0;
            for (String string : rawStrings) {
                Pair<byte[], List<StringStyledSpan>> processedString = processString(string);
                this.stringIndex.add(Integer.valueOf(stringOffset));
                stringOffset += ((byte[]) processedString.first).length;
                this.strings.add(processedString.first);
                this.styledSpans.add(processedString.second);
            }
            int styledSpanOffset = 0;
            for (List<StringStyledSpan> styledSpanList : this.styledSpans) {
                for (StringStyledSpan styledSpan : styledSpanList) {
                    this.stringIndex.add(Integer.valueOf(stringOffset));
                    stringOffset += styledSpan.styleString.length;
                    this.strings.add(styledSpan.styleString);
                }
                this.styledSpanIndex.add(Integer.valueOf(styledSpanOffset));
                styledSpanOffset += (styledSpanList.size() * 12) + 4;
            }
            int stringOffsetResidue = stringOffset % 4;
            int i = stringOffsetResidue == 0 ? 0 : 4 - stringOffsetResidue;
            this.stringsPaddingSize = i;
            int size = this.strings.size();
            this.stringCount = size;
            this.styledSpanCount = this.strings.size() - rawStrings.length;
            boolean hasStyledSpans = this.strings.size() - rawStrings.length > 0;
            if (!hasStyledSpans) {
                this.styledSpanIndex.clear();
                this.styledSpans.clear();
            }
            int size2 = (size * 4) + 28 + (this.styledSpanIndex.size() * 4);
            this.stringsStart = size2;
            int stringsSize = i + stringOffset;
            this.styledSpansStart = hasStyledSpans ? size2 + stringsSize : 0;
            int i2 = size2 + stringsSize + (hasStyledSpans ? styledSpanOffset : 0);
            this.chunkSize = i2;
            this.header = new ResChunkHeader(ColorResourcesTableCreator.HEADER_TYPE_STRING_POOL, HEADER_SIZE, i2);
        }

        void writeTo(ByteArrayOutputStream outputStream) throws IOException {
            this.header.writeTo(outputStream);
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.stringCount));
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.styledSpanCount));
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.utf8Encode ? 256 : 0));
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.stringsStart));
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.styledSpansStart));
            for (Integer index : this.stringIndex) {
                outputStream.write(ColorResourcesTableCreator.intToByteArray(index.intValue()));
            }
            for (Integer index2 : this.styledSpanIndex) {
                outputStream.write(ColorResourcesTableCreator.intToByteArray(index2.intValue()));
            }
            for (byte[] string : this.strings) {
                outputStream.write(string);
            }
            int i = this.stringsPaddingSize;
            if (i > 0) {
                outputStream.write(new byte[i]);
            }
            for (List<StringStyledSpan> styledSpanList : this.styledSpans) {
                for (StringStyledSpan styledSpan : styledSpanList) {
                    styledSpan.writeTo(outputStream);
                }
                outputStream.write(ColorResourcesTableCreator.intToByteArray(-1));
            }
        }

        int getChunkSize() {
            return this.chunkSize;
        }

        private Pair<byte[], List<StringStyledSpan>> processString(String rawString) {
            return new Pair<>(this.utf8Encode ? ColorResourcesTableCreator.stringToByteArrayUtf8(rawString) : ColorResourcesTableCreator.stringToByteArray(rawString), Collections.emptyList());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class StringStyledSpan {
        private int firstCharacterIndex;
        private int lastCharacterIndex;
        private int nameReference;
        private byte[] styleString;

        private StringStyledSpan() {
        }

        void writeTo(ByteArrayOutputStream outputStream) throws IOException {
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.nameReference));
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.firstCharacterIndex));
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.lastCharacterIndex));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class PackageChunk {
        private static final short HEADER_SIZE = 288;
        private static final int PACKAGE_NAME_MAX_LENGTH = 128;
        private final ResChunkHeader header;
        private final StringPoolChunk keyStrings;
        private final PackageInfo packageInfo;
        private final TypeSpecChunk typeSpecChunk;
        private final StringPoolChunk typeStrings = new StringPoolChunk(false, "?1", "?2", "?3", "?4", "?5", "color");

        PackageChunk(PackageInfo packageInfo, List<ColorResource> colorResources) {
            this.packageInfo = packageInfo;
            String[] keys = new String[colorResources.size()];
            for (int i = 0; i < colorResources.size(); i++) {
                keys[i] = colorResources.get(i).name;
            }
            this.keyStrings = new StringPoolChunk(true, keys);
            this.typeSpecChunk = new TypeSpecChunk(colorResources);
            this.header = new ResChunkHeader(ColorResourcesTableCreator.HEADER_TYPE_PACKAGE, HEADER_SIZE, getChunkSize());
        }

        void writeTo(ByteArrayOutputStream outputStream) throws IOException {
            this.header.writeTo(outputStream);
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.packageInfo.id));
            char[] packageName = this.packageInfo.name.toCharArray();
            for (int i = 0; i < 128; i++) {
                if (i < packageName.length) {
                    outputStream.write(ColorResourcesTableCreator.charToByteArray(packageName[i]));
                } else {
                    outputStream.write(ColorResourcesTableCreator.charToByteArray((char) 0));
                }
            }
            outputStream.write(ColorResourcesTableCreator.intToByteArray(288));
            outputStream.write(ColorResourcesTableCreator.intToByteArray(0));
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.typeStrings.getChunkSize() + 288));
            outputStream.write(ColorResourcesTableCreator.intToByteArray(0));
            outputStream.write(ColorResourcesTableCreator.intToByteArray(0));
            this.typeStrings.writeTo(outputStream);
            this.keyStrings.writeTo(outputStream);
            this.typeSpecChunk.writeTo(outputStream);
        }

        int getChunkSize() {
            return this.typeStrings.getChunkSize() + 288 + this.keyStrings.getChunkSize() + this.typeSpecChunk.getChunkSizeWithTypeChunk();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class TypeSpecChunk {
        private static final short HEADER_SIZE = 16;
        private static final int SPEC_PUBLIC = 1073741824;
        private final int entryCount;
        private final int[] entryFlags;
        private final ResChunkHeader header;
        private final TypeChunk typeChunk;

        TypeSpecChunk(List<ColorResource> colorResources) {
            this.entryCount = colorResources.get(colorResources.size() - 1).entryId + ColorResourcesTableCreator.HEADER_TYPE_STRING_POOL;
            Set<Short> validEntryIds = new HashSet<>();
            for (ColorResource colorResource : colorResources) {
                validEntryIds.add(Short.valueOf(colorResource.entryId));
            }
            this.entryFlags = new int[this.entryCount];
            for (short entryId = 0; entryId < this.entryCount; entryId = (short) (entryId + ColorResourcesTableCreator.HEADER_TYPE_STRING_POOL)) {
                if (validEntryIds.contains(Short.valueOf(entryId))) {
                    this.entryFlags[entryId] = 1073741824;
                }
            }
            this.header = new ResChunkHeader(ColorResourcesTableCreator.HEADER_TYPE_TYPE_SPEC, HEADER_SIZE, getChunkSize());
            this.typeChunk = new TypeChunk(colorResources, validEntryIds, this.entryCount);
        }

        void writeTo(ByteArrayOutputStream outputStream) throws IOException {
            int[] iArr;
            this.header.writeTo(outputStream);
            outputStream.write(new byte[]{ColorResourcesTableCreator.typeIdColor, 0, 0, 0});
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.entryCount));
            for (int entryFlag : this.entryFlags) {
                outputStream.write(ColorResourcesTableCreator.intToByteArray(entryFlag));
            }
            this.typeChunk.writeTo(outputStream);
        }

        int getChunkSizeWithTypeChunk() {
            return getChunkSize() + this.typeChunk.getChunkSize();
        }

        private int getChunkSize() {
            return (this.entryCount * 4) + 16;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class TypeChunk {
        private static final byte CONFIG_SIZE = 64;
        private static final short HEADER_SIZE = 84;
        private static final int OFFSET_NO_ENTRY = -1;
        private final byte[] config;
        private final int entryCount;
        private final ResChunkHeader header;
        private final int[] offsetTable;
        private final ResEntry[] resEntries;

        TypeChunk(List<ColorResource> colorResources, Set<Short> entryIds, int entryCount) {
            byte[] bArr = new byte[64];
            this.config = bArr;
            this.entryCount = entryCount;
            bArr[0] = CONFIG_SIZE;
            this.resEntries = new ResEntry[colorResources.size()];
            for (int index = 0; index < colorResources.size(); index++) {
                ColorResource colorResource = colorResources.get(index);
                this.resEntries[index] = new ResEntry(index, colorResource.value);
            }
            this.offsetTable = new int[entryCount];
            int currentOffset = 0;
            for (short entryId = 0; entryId < entryCount; entryId = (short) (entryId + ColorResourcesTableCreator.HEADER_TYPE_STRING_POOL)) {
                if (entryIds.contains(Short.valueOf(entryId))) {
                    this.offsetTable[entryId] = currentOffset;
                    currentOffset += 16;
                } else {
                    this.offsetTable[entryId] = -1;
                }
            }
            this.header = new ResChunkHeader(ColorResourcesTableCreator.HEADER_TYPE_TYPE, HEADER_SIZE, getChunkSize());
        }

        void writeTo(ByteArrayOutputStream outputStream) throws IOException {
            int[] iArr;
            ResEntry[] resEntryArr;
            this.header.writeTo(outputStream);
            outputStream.write(new byte[]{ColorResourcesTableCreator.typeIdColor, 0, 0, 0});
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.entryCount));
            outputStream.write(ColorResourcesTableCreator.intToByteArray(getEntryStart()));
            outputStream.write(this.config);
            for (int offset : this.offsetTable) {
                outputStream.write(ColorResourcesTableCreator.intToByteArray(offset));
            }
            for (ResEntry entry : this.resEntries) {
                entry.writeTo(outputStream);
            }
        }

        int getChunkSize() {
            return getEntryStart() + (this.resEntries.length * 16);
        }

        private int getEntryStart() {
            return getOffsetTableSize() + 84;
        }

        private int getOffsetTableSize() {
            return this.offsetTable.length * 4;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class ResEntry {
        private static final byte DATA_TYPE_AARRGGBB = 28;
        private static final short ENTRY_SIZE = 8;
        private static final short FLAG_PUBLIC = 2;
        private static final int SIZE = 16;
        private static final short VALUE_SIZE = 8;
        private final int data;
        private final int keyStringIndex;

        ResEntry(int keyStringIndex, int data) {
            this.keyStringIndex = keyStringIndex;
            this.data = data;
        }

        void writeTo(ByteArrayOutputStream outputStream) throws IOException {
            outputStream.write(ColorResourcesTableCreator.shortToByteArray((short) 8));
            outputStream.write(ColorResourcesTableCreator.shortToByteArray(FLAG_PUBLIC));
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.keyStringIndex));
            outputStream.write(ColorResourcesTableCreator.shortToByteArray((short) 8));
            outputStream.write(new byte[]{0, DATA_TYPE_AARRGGBB});
            outputStream.write(ColorResourcesTableCreator.intToByteArray(this.data));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class PackageInfo {
        private final int id;
        private final String name;

        PackageInfo(int id, String name) {
            this.id = id;
            this.name = name;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class ColorResource {
        private final short entryId;
        private final String name;
        private final byte packageId;
        private final byte typeId;
        private final int value;

        ColorResource(int id, String name, int value) {
            this.name = name;
            this.value = value;
            this.entryId = (short) (65535 & id);
            this.typeId = (byte) ((id >> 16) & 255);
            this.packageId = (byte) ((id >> 24) & 255);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static byte[] shortToByteArray(short value) {
        return new byte[]{(byte) (value & 255), (byte) ((value >> 8) & 255)};
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static byte[] charToByteArray(char value) {
        return new byte[]{(byte) (value & 255), (byte) ((value >> '\b') & 255)};
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static byte[] intToByteArray(int value) {
        return new byte[]{(byte) (value & 255), (byte) ((value >> 8) & 255), (byte) ((value >> 16) & 255), (byte) ((value >> 24) & 255)};
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static byte[] stringToByteArray(String value) {
        char[] chars = value.toCharArray();
        byte[] bytes = new byte[(chars.length * 2) + 4];
        byte[] lengthBytes = shortToByteArray((short) chars.length);
        bytes[0] = lengthBytes[0];
        bytes[1] = lengthBytes[1];
        for (int i = 0; i < chars.length; i++) {
            byte[] charBytes = charToByteArray(chars[i]);
            bytes[(i * 2) + 2] = charBytes[0];
            bytes[(i * 2) + 3] = charBytes[1];
        }
        int i2 = bytes.length;
        bytes[i2 - 2] = 0;
        bytes[bytes.length - 1] = 0;
        return bytes;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static byte[] stringToByteArrayUtf8(String value) {
        byte[] rawBytes = value.getBytes(Charset.forName("UTF-8"));
        byte stringLength = (byte) rawBytes.length;
        byte[] bytes = new byte[rawBytes.length + 3];
        System.arraycopy(rawBytes, 0, bytes, 2, stringLength);
        bytes[1] = stringLength;
        bytes[0] = stringLength;
        bytes[bytes.length - 1] = 0;
        return bytes;
    }
}
