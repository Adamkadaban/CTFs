package androidx.core.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.media.AudioAttributes;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import androidx.core.util.Preconditions;
/* loaded from: classes.dex */
public class NotificationChannelCompat {
    public static final String DEFAULT_CHANNEL_ID = "miscellaneous";
    private static final int DEFAULT_LIGHT_COLOR = 0;
    private static final boolean DEFAULT_SHOW_BADGE = true;
    AudioAttributes mAudioAttributes;
    private boolean mBypassDnd;
    private boolean mCanBubble;
    String mConversationId;
    String mDescription;
    String mGroupId;
    final String mId;
    int mImportance;
    private boolean mImportantConversation;
    int mLightColor;
    boolean mLights;
    private int mLockscreenVisibility;
    CharSequence mName;
    String mParentId;
    boolean mShowBadge;
    Uri mSound;
    boolean mVibrationEnabled;
    long[] mVibrationPattern;

    /* loaded from: classes.dex */
    public static class Builder {
        private final NotificationChannelCompat mChannel;

        public Builder(String id, int importance) {
            this.mChannel = new NotificationChannelCompat(id, importance);
        }

        public Builder setName(CharSequence name) {
            this.mChannel.mName = name;
            return this;
        }

        public Builder setImportance(int importance) {
            this.mChannel.mImportance = importance;
            return this;
        }

        public Builder setDescription(String description) {
            this.mChannel.mDescription = description;
            return this;
        }

        public Builder setGroup(String groupId) {
            this.mChannel.mGroupId = groupId;
            return this;
        }

        public Builder setShowBadge(boolean showBadge) {
            this.mChannel.mShowBadge = showBadge;
            return this;
        }

        public Builder setSound(Uri sound, AudioAttributes audioAttributes) {
            this.mChannel.mSound = sound;
            this.mChannel.mAudioAttributes = audioAttributes;
            return this;
        }

        public Builder setLightsEnabled(boolean lights) {
            this.mChannel.mLights = lights;
            return this;
        }

        public Builder setLightColor(int argb) {
            this.mChannel.mLightColor = argb;
            return this;
        }

        public Builder setVibrationEnabled(boolean vibration) {
            this.mChannel.mVibrationEnabled = vibration;
            return this;
        }

        public Builder setVibrationPattern(long[] vibrationPattern) {
            this.mChannel.mVibrationEnabled = (vibrationPattern == null || vibrationPattern.length <= 0) ? false : NotificationChannelCompat.DEFAULT_SHOW_BADGE;
            this.mChannel.mVibrationPattern = vibrationPattern;
            return this;
        }

        public Builder setConversationId(String parentChannelId, String conversationId) {
            if (Build.VERSION.SDK_INT >= 30) {
                this.mChannel.mParentId = parentChannelId;
                this.mChannel.mConversationId = conversationId;
            }
            return this;
        }

        public NotificationChannelCompat build() {
            return this.mChannel;
        }
    }

    NotificationChannelCompat(String id, int importance) {
        this.mShowBadge = DEFAULT_SHOW_BADGE;
        this.mSound = Settings.System.DEFAULT_NOTIFICATION_URI;
        this.mLightColor = 0;
        this.mId = (String) Preconditions.checkNotNull(id);
        this.mImportance = importance;
        if (Build.VERSION.SDK_INT >= 21) {
            this.mAudioAttributes = Notification.AUDIO_ATTRIBUTES_DEFAULT;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public NotificationChannelCompat(NotificationChannel channel) {
        this(channel.getId(), channel.getImportance());
        this.mName = channel.getName();
        this.mDescription = channel.getDescription();
        this.mGroupId = channel.getGroup();
        this.mShowBadge = channel.canShowBadge();
        this.mSound = channel.getSound();
        this.mAudioAttributes = channel.getAudioAttributes();
        this.mLights = channel.shouldShowLights();
        this.mLightColor = channel.getLightColor();
        this.mVibrationEnabled = channel.shouldVibrate();
        this.mVibrationPattern = channel.getVibrationPattern();
        if (Build.VERSION.SDK_INT >= 30) {
            this.mParentId = channel.getParentChannelId();
            this.mConversationId = channel.getConversationId();
        }
        this.mBypassDnd = channel.canBypassDnd();
        this.mLockscreenVisibility = channel.getLockscreenVisibility();
        if (Build.VERSION.SDK_INT >= 29) {
            this.mCanBubble = channel.canBubble();
        }
        if (Build.VERSION.SDK_INT >= 30) {
            this.mImportantConversation = channel.isImportantConversation();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public NotificationChannel getNotificationChannel() {
        String str;
        String str2;
        if (Build.VERSION.SDK_INT < 26) {
            return null;
        }
        NotificationChannel channel = new NotificationChannel(this.mId, this.mName, this.mImportance);
        channel.setDescription(this.mDescription);
        channel.setGroup(this.mGroupId);
        channel.setShowBadge(this.mShowBadge);
        channel.setSound(this.mSound, this.mAudioAttributes);
        channel.enableLights(this.mLights);
        channel.setLightColor(this.mLightColor);
        channel.setVibrationPattern(this.mVibrationPattern);
        channel.enableVibration(this.mVibrationEnabled);
        if (Build.VERSION.SDK_INT >= 30 && (str = this.mParentId) != null && (str2 = this.mConversationId) != null) {
            channel.setConversationId(str, str2);
        }
        return channel;
    }

    public Builder toBuilder() {
        return new Builder(this.mId, this.mImportance).setName(this.mName).setDescription(this.mDescription).setGroup(this.mGroupId).setShowBadge(this.mShowBadge).setSound(this.mSound, this.mAudioAttributes).setLightsEnabled(this.mLights).setLightColor(this.mLightColor).setVibrationEnabled(this.mVibrationEnabled).setVibrationPattern(this.mVibrationPattern).setConversationId(this.mParentId, this.mConversationId);
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

    public int getImportance() {
        return this.mImportance;
    }

    public Uri getSound() {
        return this.mSound;
    }

    public AudioAttributes getAudioAttributes() {
        return this.mAudioAttributes;
    }

    public boolean shouldShowLights() {
        return this.mLights;
    }

    public int getLightColor() {
        return this.mLightColor;
    }

    public boolean shouldVibrate() {
        return this.mVibrationEnabled;
    }

    public long[] getVibrationPattern() {
        return this.mVibrationPattern;
    }

    public boolean canShowBadge() {
        return this.mShowBadge;
    }

    public String getGroup() {
        return this.mGroupId;
    }

    public String getParentChannelId() {
        return this.mParentId;
    }

    public String getConversationId() {
        return this.mConversationId;
    }

    public boolean canBypassDnd() {
        return this.mBypassDnd;
    }

    public int getLockscreenVisibility() {
        return this.mLockscreenVisibility;
    }

    public boolean canBubble() {
        return this.mCanBubble;
    }

    public boolean isImportantConversation() {
        return this.mImportantConversation;
    }
}
