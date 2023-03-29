package androidx.core.app;

import android.app.NotificationChannel;
import android.app.NotificationChannelGroup;
import android.os.Build;
import androidx.core.util.Preconditions;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public class NotificationChannelGroupCompat {
    private boolean mBlocked;
    private List<NotificationChannelCompat> mChannels;
    String mDescription;
    final String mId;
    CharSequence mName;

    /* loaded from: classes.dex */
    public static class Builder {
        final NotificationChannelGroupCompat mGroup;

        public Builder(String id) {
            this.mGroup = new NotificationChannelGroupCompat(id);
        }

        public Builder setName(CharSequence name) {
            this.mGroup.mName = name;
            return this;
        }

        public Builder setDescription(String description) {
            this.mGroup.mDescription = description;
            return this;
        }

        public NotificationChannelGroupCompat build() {
            return this.mGroup;
        }
    }

    NotificationChannelGroupCompat(String id) {
        this.mChannels = Collections.emptyList();
        this.mId = (String) Preconditions.checkNotNull(id);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public NotificationChannelGroupCompat(NotificationChannelGroup group) {
        this(group, Collections.emptyList());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public NotificationChannelGroupCompat(NotificationChannelGroup group, List<NotificationChannel> allChannels) {
        this(group.getId());
        this.mName = group.getName();
        if (Build.VERSION.SDK_INT >= 28) {
            this.mDescription = group.getDescription();
        }
        if (Build.VERSION.SDK_INT >= 28) {
            this.mBlocked = group.isBlocked();
            this.mChannels = getChannelsCompat(group.getChannels());
            return;
        }
        this.mChannels = getChannelsCompat(allChannels);
    }

    private List<NotificationChannelCompat> getChannelsCompat(List<NotificationChannel> channels) {
        List<NotificationChannelCompat> channelsCompat = new ArrayList<>();
        for (NotificationChannel channel : channels) {
            if (this.mId.equals(channel.getGroup())) {
                channelsCompat.add(new NotificationChannelCompat(channel));
            }
        }
        return channelsCompat;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public NotificationChannelGroup getNotificationChannelGroup() {
        if (Build.VERSION.SDK_INT < 26) {
            return null;
        }
        NotificationChannelGroup group = new NotificationChannelGroup(this.mId, this.mName);
        if (Build.VERSION.SDK_INT >= 28) {
            group.setDescription(this.mDescription);
        }
        return group;
    }

    public Builder toBuilder() {
        return new Builder(this.mId).setName(this.mName).setDescription(this.mDescription);
    }

    public String getId() {
        return this.mId;
    }

    public CharSequence getName() {
        return this.mName;
    }

    public String getDescription() {
        return this.mDescription;
    }

    public boolean isBlocked() {
        return this.mBlocked;
    }

    public List<NotificationChannelCompat> getChannels() {
        return this.mChannels;
    }
}
