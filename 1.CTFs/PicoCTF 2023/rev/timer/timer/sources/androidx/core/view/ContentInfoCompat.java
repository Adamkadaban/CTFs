package androidx.core.view;

import android.content.ClipData;
import android.content.ClipDescription;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.util.Pair;
import android.view.ContentInfo;
import androidx.core.util.Preconditions;
import androidx.core.util.Predicate;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
/* loaded from: classes.dex */
public final class ContentInfoCompat {
    public static final int FLAG_CONVERT_TO_PLAIN_TEXT = 1;
    public static final int SOURCE_APP = 0;
    public static final int SOURCE_AUTOFILL = 4;
    public static final int SOURCE_CLIPBOARD = 1;
    public static final int SOURCE_DRAG_AND_DROP = 3;
    public static final int SOURCE_INPUT_METHOD = 2;
    public static final int SOURCE_PROCESS_TEXT = 5;
    private final Compat mCompat;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public interface BuilderCompat {
        ContentInfoCompat build();

        void setClip(ClipData clipData);

        void setExtras(Bundle bundle);

        void setFlags(int i);

        void setLinkUri(Uri uri);

        void setSource(int i);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public interface Compat {
        ClipData getClip();

        Bundle getExtras();

        int getFlags();

        Uri getLinkUri();

        int getSource();

        ContentInfo getWrapped();
    }

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface Flags {
    }

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface Source {
    }

    static String sourceToString(int source) {
        switch (source) {
            case 0:
                return "SOURCE_APP";
            case 1:
                return "SOURCE_CLIPBOARD";
            case 2:
                return "SOURCE_INPUT_METHOD";
            case 3:
                return "SOURCE_DRAG_AND_DROP";
            case 4:
                return "SOURCE_AUTOFILL";
            case 5:
                return "SOURCE_PROCESS_TEXT";
            default:
                return String.valueOf(source);
        }
    }

    static String flagsToString(int flags) {
        if ((flags & 1) != 0) {
            return "FLAG_CONVERT_TO_PLAIN_TEXT";
        }
        return String.valueOf(flags);
    }

    ContentInfoCompat(Compat compat) {
        this.mCompat = compat;
    }

    public static ContentInfoCompat toContentInfoCompat(ContentInfo platContentInfo) {
        return new ContentInfoCompat(new Compat31Impl(platContentInfo));
    }

    public ContentInfo toContentInfo() {
        return this.mCompat.getWrapped();
    }

    public String toString() {
        return this.mCompat.toString();
    }

    public ClipData getClip() {
        return this.mCompat.getClip();
    }

    public int getSource() {
        return this.mCompat.getSource();
    }

    public int getFlags() {
        return this.mCompat.getFlags();
    }

    public Uri getLinkUri() {
        return this.mCompat.getLinkUri();
    }

    public Bundle getExtras() {
        return this.mCompat.getExtras();
    }

    public Pair<ContentInfoCompat, ContentInfoCompat> partition(Predicate<ClipData.Item> itemPredicate) {
        ClipData clip = this.mCompat.getClip();
        if (clip.getItemCount() == 1) {
            boolean matched = itemPredicate.test(clip.getItemAt(0));
            return Pair.create(matched ? this : null, matched ? null : this);
        }
        Pair<ClipData, ClipData> split = partition(clip, itemPredicate);
        if (split.first == null) {
            return Pair.create(null, this);
        }
        if (split.second == null) {
            return Pair.create(this, null);
        }
        return Pair.create(new Builder(this).setClip((ClipData) split.first).build(), new Builder(this).setClip((ClipData) split.second).build());
    }

    static Pair<ClipData, ClipData> partition(ClipData clip, Predicate<ClipData.Item> itemPredicate) {
        ArrayList<ClipData.Item> acceptedItems = null;
        ArrayList<ClipData.Item> remainingItems = null;
        for (int i = 0; i < clip.getItemCount(); i++) {
            ClipData.Item item = clip.getItemAt(i);
            if (itemPredicate.test(item)) {
                acceptedItems = acceptedItems == null ? new ArrayList<>() : acceptedItems;
                acceptedItems.add(item);
            } else {
                remainingItems = remainingItems == null ? new ArrayList<>() : remainingItems;
                remainingItems.add(item);
            }
        }
        if (acceptedItems == null) {
            return Pair.create(null, clip);
        }
        if (remainingItems == null) {
            return Pair.create(clip, null);
        }
        return Pair.create(buildClipData(clip.getDescription(), acceptedItems), buildClipData(clip.getDescription(), remainingItems));
    }

    static ClipData buildClipData(ClipDescription description, List<ClipData.Item> items) {
        ClipData clip = new ClipData(new ClipDescription(description), items.get(0));
        for (int i = 1; i < items.size(); i++) {
            clip.addItem(items.get(i));
        }
        return clip;
    }

    public static Pair<ContentInfo, ContentInfo> partition(ContentInfo payload, java.util.function.Predicate<ClipData.Item> itemPredicate) {
        return Api31Impl.partition(payload, itemPredicate);
    }

    /* loaded from: classes.dex */
    private static final class Api31Impl {
        private Api31Impl() {
        }

        public static Pair<ContentInfo, ContentInfo> partition(ContentInfo payload, final java.util.function.Predicate<ClipData.Item> itemPredicate) {
            ClipData clip = payload.getClip();
            if (clip.getItemCount() == 1) {
                boolean matched = itemPredicate.test(clip.getItemAt(0));
                return Pair.create(matched ? payload : null, matched ? null : payload);
            }
            Objects.requireNonNull(itemPredicate);
            Pair<ClipData, ClipData> split = ContentInfoCompat.partition(clip, new Predicate() { // from class: androidx.core.view.ContentInfoCompat$Api31Impl$$ExternalSyntheticLambda0
                @Override // androidx.core.util.Predicate
                public final boolean test(Object obj) {
                    return itemPredicate.test((ClipData.Item) obj);
                }
            });
            if (split.first == null) {
                return Pair.create(null, payload);
            }
            if (split.second == null) {
                return Pair.create(payload, null);
            }
            return Pair.create(new ContentInfo.Builder(payload).setClip((ClipData) split.first).build(), new ContentInfo.Builder(payload).setClip((ClipData) split.second).build());
        }
    }

    /* loaded from: classes.dex */
    private static final class CompatImpl implements Compat {
        private final ClipData mClip;
        private final Bundle mExtras;
        private final int mFlags;
        private final Uri mLinkUri;
        private final int mSource;

        CompatImpl(BuilderCompatImpl b) {
            this.mClip = (ClipData) Preconditions.checkNotNull(b.mClip);
            this.mSource = Preconditions.checkArgumentInRange(b.mSource, 0, 5, "source");
            this.mFlags = Preconditions.checkFlagsArgument(b.mFlags, 1);
            this.mLinkUri = b.mLinkUri;
            this.mExtras = b.mExtras;
        }

        @Override // androidx.core.view.ContentInfoCompat.Compat
        public ContentInfo getWrapped() {
            return null;
        }

        @Override // androidx.core.view.ContentInfoCompat.Compat
        public ClipData getClip() {
            return this.mClip;
        }

        @Override // androidx.core.view.ContentInfoCompat.Compat
        public int getSource() {
            return this.mSource;
        }

        @Override // androidx.core.view.ContentInfoCompat.Compat
        public int getFlags() {
            return this.mFlags;
        }

        @Override // androidx.core.view.ContentInfoCompat.Compat
        public Uri getLinkUri() {
            return this.mLinkUri;
        }

        @Override // androidx.core.view.ContentInfoCompat.Compat
        public Bundle getExtras() {
            return this.mExtras;
        }

        public String toString() {
            String str;
            StringBuilder sb = new StringBuilder();
            sb.append("ContentInfoCompat{clip=");
            sb.append(this.mClip.getDescription());
            sb.append(", source=");
            sb.append(ContentInfoCompat.sourceToString(this.mSource));
            sb.append(", flags=");
            sb.append(ContentInfoCompat.flagsToString(this.mFlags));
            if (this.mLinkUri == null) {
                str = "";
            } else {
                str = ", hasLinkUri(" + this.mLinkUri.toString().length() + ")";
            }
            sb.append(str);
            sb.append(this.mExtras != null ? ", hasExtras" : "");
            sb.append("}");
            return sb.toString();
        }
    }

    /* loaded from: classes.dex */
    private static final class Compat31Impl implements Compat {
        private final ContentInfo mWrapped;

        Compat31Impl(ContentInfo wrapped) {
            this.mWrapped = (ContentInfo) Preconditions.checkNotNull(wrapped);
        }

        @Override // androidx.core.view.ContentInfoCompat.Compat
        public ContentInfo getWrapped() {
            return this.mWrapped;
        }

        @Override // androidx.core.view.ContentInfoCompat.Compat
        public ClipData getClip() {
            return this.mWrapped.getClip();
        }

        @Override // androidx.core.view.ContentInfoCompat.Compat
        public int getSource() {
            return this.mWrapped.getSource();
        }

        @Override // androidx.core.view.ContentInfoCompat.Compat
        public int getFlags() {
            return this.mWrapped.getFlags();
        }

        @Override // androidx.core.view.ContentInfoCompat.Compat
        public Uri getLinkUri() {
            return this.mWrapped.getLinkUri();
        }

        @Override // androidx.core.view.ContentInfoCompat.Compat
        public Bundle getExtras() {
            return this.mWrapped.getExtras();
        }

        public String toString() {
            return "ContentInfoCompat{" + this.mWrapped + "}";
        }
    }

    /* loaded from: classes.dex */
    public static final class Builder {
        private final BuilderCompat mBuilderCompat;

        public Builder(ContentInfoCompat other) {
            if (Build.VERSION.SDK_INT >= 31) {
                this.mBuilderCompat = new BuilderCompat31Impl(other);
            } else {
                this.mBuilderCompat = new BuilderCompatImpl(other);
            }
        }

        public Builder(ClipData clip, int source) {
            if (Build.VERSION.SDK_INT >= 31) {
                this.mBuilderCompat = new BuilderCompat31Impl(clip, source);
            } else {
                this.mBuilderCompat = new BuilderCompatImpl(clip, source);
            }
        }

        public Builder setClip(ClipData clip) {
            this.mBuilderCompat.setClip(clip);
            return this;
        }

        public Builder setSource(int source) {
            this.mBuilderCompat.setSource(source);
            return this;
        }

        public Builder setFlags(int flags) {
            this.mBuilderCompat.setFlags(flags);
            return this;
        }

        public Builder setLinkUri(Uri linkUri) {
            this.mBuilderCompat.setLinkUri(linkUri);
            return this;
        }

        public Builder setExtras(Bundle extras) {
            this.mBuilderCompat.setExtras(extras);
            return this;
        }

        public ContentInfoCompat build() {
            return this.mBuilderCompat.build();
        }
    }

    /* loaded from: classes.dex */
    private static final class BuilderCompatImpl implements BuilderCompat {
        ClipData mClip;
        Bundle mExtras;
        int mFlags;
        Uri mLinkUri;
        int mSource;

        BuilderCompatImpl(ClipData clip, int source) {
            this.mClip = clip;
            this.mSource = source;
        }

        BuilderCompatImpl(ContentInfoCompat other) {
            this.mClip = other.getClip();
            this.mSource = other.getSource();
            this.mFlags = other.getFlags();
            this.mLinkUri = other.getLinkUri();
            this.mExtras = other.getExtras();
        }

        @Override // androidx.core.view.ContentInfoCompat.BuilderCompat
        public void setClip(ClipData clip) {
            this.mClip = clip;
        }

        @Override // androidx.core.view.ContentInfoCompat.BuilderCompat
        public void setSource(int source) {
            this.mSource = source;
        }

        @Override // androidx.core.view.ContentInfoCompat.BuilderCompat
        public void setFlags(int flags) {
            this.mFlags = flags;
        }

        @Override // androidx.core.view.ContentInfoCompat.BuilderCompat
        public void setLinkUri(Uri linkUri) {
            this.mLinkUri = linkUri;
        }

        @Override // androidx.core.view.ContentInfoCompat.BuilderCompat
        public void setExtras(Bundle extras) {
            this.mExtras = extras;
        }

        @Override // androidx.core.view.ContentInfoCompat.BuilderCompat
        public ContentInfoCompat build() {
            return new ContentInfoCompat(new CompatImpl(this));
        }
    }

    /* loaded from: classes.dex */
    private static final class BuilderCompat31Impl implements BuilderCompat {
        private final ContentInfo.Builder mPlatformBuilder;

        BuilderCompat31Impl(ClipData clip, int source) {
            this.mPlatformBuilder = new ContentInfo.Builder(clip, source);
        }

        BuilderCompat31Impl(ContentInfoCompat other) {
            this.mPlatformBuilder = new ContentInfo.Builder(other.toContentInfo());
        }

        @Override // androidx.core.view.ContentInfoCompat.BuilderCompat
        public void setClip(ClipData clip) {
            this.mPlatformBuilder.setClip(clip);
        }

        @Override // androidx.core.view.ContentInfoCompat.BuilderCompat
        public void setSource(int source) {
            this.mPlatformBuilder.setSource(source);
        }

        @Override // androidx.core.view.ContentInfoCompat.BuilderCompat
        public void setFlags(int flags) {
            this.mPlatformBuilder.setFlags(flags);
        }

        @Override // androidx.core.view.ContentInfoCompat.BuilderCompat
        public void setLinkUri(Uri linkUri) {
            this.mPlatformBuilder.setLinkUri(linkUri);
        }

        @Override // androidx.core.view.ContentInfoCompat.BuilderCompat
        public void setExtras(Bundle extras) {
            this.mPlatformBuilder.setExtras(extras);
        }

        @Override // androidx.core.view.ContentInfoCompat.BuilderCompat
        public ContentInfoCompat build() {
            return new ContentInfoCompat(new Compat31Impl(this.mPlatformBuilder.build()));
        }
    }
}
