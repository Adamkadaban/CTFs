package androidx.core.content.pm;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ShortcutInfo;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.PersistableBundle;
import android.os.UserHandle;
import android.text.TextUtils;
import androidx.core.app.Person;
import androidx.core.content.LocusIdCompat;
import androidx.core.graphics.drawable.IconCompat;
import androidx.core.net.UriCompat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
/* loaded from: classes.dex */
public class ShortcutInfoCompat {
    private static final String EXTRA_LOCUS_ID = "extraLocusId";
    private static final String EXTRA_LONG_LIVED = "extraLongLived";
    private static final String EXTRA_PERSON_ = "extraPerson_";
    private static final String EXTRA_PERSON_COUNT = "extraPersonCount";
    private static final String EXTRA_SLICE_URI = "extraSliceUri";
    ComponentName mActivity;
    Set<String> mCategories;
    Context mContext;
    CharSequence mDisabledMessage;
    int mDisabledReason;
    PersistableBundle mExtras;
    boolean mHasKeyFieldsOnly;
    IconCompat mIcon;
    String mId;
    Intent[] mIntents;
    boolean mIsAlwaysBadged;
    boolean mIsCached;
    boolean mIsDeclaredInManifest;
    boolean mIsDynamic;
    boolean mIsEnabled = true;
    boolean mIsImmutable;
    boolean mIsLongLived;
    boolean mIsPinned;
    CharSequence mLabel;
    long mLastChangedTimestamp;
    LocusIdCompat mLocusId;
    CharSequence mLongLabel;
    String mPackageName;
    Person[] mPersons;
    int mRank;
    UserHandle mUser;

    ShortcutInfoCompat() {
    }

    public ShortcutInfo toShortcutInfo() {
        ShortcutInfo.Builder builder = new ShortcutInfo.Builder(this.mContext, this.mId).setShortLabel(this.mLabel).setIntents(this.mIntents);
        IconCompat iconCompat = this.mIcon;
        if (iconCompat != null) {
            builder.setIcon(iconCompat.toIcon(this.mContext));
        }
        if (!TextUtils.isEmpty(this.mLongLabel)) {
            builder.setLongLabel(this.mLongLabel);
        }
        if (!TextUtils.isEmpty(this.mDisabledMessage)) {
            builder.setDisabledMessage(this.mDisabledMessage);
        }
        ComponentName componentName = this.mActivity;
        if (componentName != null) {
            builder.setActivity(componentName);
        }
        Set<String> set = this.mCategories;
        if (set != null) {
            builder.setCategories(set);
        }
        builder.setRank(this.mRank);
        PersistableBundle persistableBundle = this.mExtras;
        if (persistableBundle != null) {
            builder.setExtras(persistableBundle);
        }
        if (Build.VERSION.SDK_INT >= 29) {
            Person[] personArr = this.mPersons;
            if (personArr != null && personArr.length > 0) {
                android.app.Person[] persons = new android.app.Person[personArr.length];
                for (int i = 0; i < persons.length; i++) {
                    persons[i] = this.mPersons[i].toAndroidPerson();
                }
                builder.setPersons(persons);
            }
            LocusIdCompat locusIdCompat = this.mLocusId;
            if (locusIdCompat != null) {
                builder.setLocusId(locusIdCompat.toLocusId());
            }
            builder.setLongLived(this.mIsLongLived);
        } else {
            builder.setExtras(buildLegacyExtrasBundle());
        }
        return builder.build();
    }

    private PersistableBundle buildLegacyExtrasBundle() {
        if (this.mExtras == null) {
            this.mExtras = new PersistableBundle();
        }
        Person[] personArr = this.mPersons;
        if (personArr != null && personArr.length > 0) {
            this.mExtras.putInt(EXTRA_PERSON_COUNT, personArr.length);
            for (int i = 0; i < this.mPersons.length; i++) {
                PersistableBundle persistableBundle = this.mExtras;
                persistableBundle.putPersistableBundle(EXTRA_PERSON_ + (i + 1), this.mPersons[i].toPersistableBundle());
            }
        }
        LocusIdCompat locusIdCompat = this.mLocusId;
        if (locusIdCompat != null) {
            this.mExtras.putString(EXTRA_LOCUS_ID, locusIdCompat.getId());
        }
        this.mExtras.putBoolean(EXTRA_LONG_LIVED, this.mIsLongLived);
        return this.mExtras;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Intent addToIntent(Intent outIntent) {
        Intent[] intentArr = this.mIntents;
        outIntent.putExtra("android.intent.extra.shortcut.INTENT", intentArr[intentArr.length - 1]).putExtra("android.intent.extra.shortcut.NAME", this.mLabel.toString());
        if (this.mIcon != null) {
            Drawable badge = null;
            if (this.mIsAlwaysBadged) {
                PackageManager pm = this.mContext.getPackageManager();
                ComponentName componentName = this.mActivity;
                if (componentName != null) {
                    try {
                        badge = pm.getActivityIcon(componentName);
                    } catch (PackageManager.NameNotFoundException e) {
                    }
                }
                if (badge == null) {
                    badge = this.mContext.getApplicationInfo().loadIcon(pm);
                }
            }
            this.mIcon.addToShortcutIntent(outIntent, badge, this.mContext);
        }
        return outIntent;
    }

    public String getId() {
        return this.mId;
    }

    public String getPackage() {
        return this.mPackageName;
    }

    public ComponentName getActivity() {
        return this.mActivity;
    }

    public CharSequence getShortLabel() {
        return this.mLabel;
    }

    public CharSequence getLongLabel() {
        return this.mLongLabel;
    }

    public CharSequence getDisabledMessage() {
        return this.mDisabledMessage;
    }

    public int getDisabledReason() {
        return this.mDisabledReason;
    }

    public Intent getIntent() {
        Intent[] intentArr = this.mIntents;
        return intentArr[intentArr.length - 1];
    }

    public Intent[] getIntents() {
        Intent[] intentArr = this.mIntents;
        return (Intent[]) Arrays.copyOf(intentArr, intentArr.length);
    }

    public Set<String> getCategories() {
        return this.mCategories;
    }

    public LocusIdCompat getLocusId() {
        return this.mLocusId;
    }

    public int getRank() {
        return this.mRank;
    }

    public IconCompat getIcon() {
        return this.mIcon;
    }

    static Person[] getPersonsFromExtra(PersistableBundle bundle) {
        if (bundle == null || !bundle.containsKey(EXTRA_PERSON_COUNT)) {
            return null;
        }
        int personsLength = bundle.getInt(EXTRA_PERSON_COUNT);
        Person[] persons = new Person[personsLength];
        for (int i = 0; i < personsLength; i++) {
            persons[i] = Person.fromPersistableBundle(bundle.getPersistableBundle(EXTRA_PERSON_ + (i + 1)));
        }
        return persons;
    }

    static boolean getLongLivedFromExtra(PersistableBundle bundle) {
        if (bundle == null || !bundle.containsKey(EXTRA_LONG_LIVED)) {
            return false;
        }
        return bundle.getBoolean(EXTRA_LONG_LIVED);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static List<ShortcutInfoCompat> fromShortcuts(Context context, List<ShortcutInfo> shortcuts) {
        List<ShortcutInfoCompat> results = new ArrayList<>(shortcuts.size());
        for (ShortcutInfo s : shortcuts) {
            results.add(new Builder(context, s).build());
        }
        return results;
    }

    public PersistableBundle getExtras() {
        return this.mExtras;
    }

    public UserHandle getUserHandle() {
        return this.mUser;
    }

    public long getLastChangedTimestamp() {
        return this.mLastChangedTimestamp;
    }

    public boolean isCached() {
        return this.mIsCached;
    }

    public boolean isDynamic() {
        return this.mIsDynamic;
    }

    public boolean isPinned() {
        return this.mIsPinned;
    }

    public boolean isDeclaredInManifest() {
        return this.mIsDeclaredInManifest;
    }

    public boolean isImmutable() {
        return this.mIsImmutable;
    }

    public boolean isEnabled() {
        return this.mIsEnabled;
    }

    public boolean hasKeyFieldsOnly() {
        return this.mHasKeyFieldsOnly;
    }

    static LocusIdCompat getLocusId(ShortcutInfo shortcutInfo) {
        if (Build.VERSION.SDK_INT >= 29) {
            if (shortcutInfo.getLocusId() == null) {
                return null;
            }
            return LocusIdCompat.toLocusIdCompat(shortcutInfo.getLocusId());
        }
        return getLocusIdFromExtra(shortcutInfo.getExtras());
    }

    private static LocusIdCompat getLocusIdFromExtra(PersistableBundle bundle) {
        String locusId;
        if (bundle == null || (locusId = bundle.getString(EXTRA_LOCUS_ID)) == null) {
            return null;
        }
        return new LocusIdCompat(locusId);
    }

    /* loaded from: classes.dex */
    public static class Builder {
        private Map<String, Map<String, List<String>>> mCapabilityBindingParams;
        private Set<String> mCapabilityBindings;
        private final ShortcutInfoCompat mInfo;
        private boolean mIsConversation;
        private Uri mSliceUri;

        public Builder(Context context, String id) {
            ShortcutInfoCompat shortcutInfoCompat = new ShortcutInfoCompat();
            this.mInfo = shortcutInfoCompat;
            shortcutInfoCompat.mContext = context;
            shortcutInfoCompat.mId = id;
        }

        public Builder(ShortcutInfoCompat shortcutInfo) {
            ShortcutInfoCompat shortcutInfoCompat = new ShortcutInfoCompat();
            this.mInfo = shortcutInfoCompat;
            shortcutInfoCompat.mContext = shortcutInfo.mContext;
            shortcutInfoCompat.mId = shortcutInfo.mId;
            shortcutInfoCompat.mPackageName = shortcutInfo.mPackageName;
            shortcutInfoCompat.mIntents = (Intent[]) Arrays.copyOf(shortcutInfo.mIntents, shortcutInfo.mIntents.length);
            shortcutInfoCompat.mActivity = shortcutInfo.mActivity;
            shortcutInfoCompat.mLabel = shortcutInfo.mLabel;
            shortcutInfoCompat.mLongLabel = shortcutInfo.mLongLabel;
            shortcutInfoCompat.mDisabledMessage = shortcutInfo.mDisabledMessage;
            shortcutInfoCompat.mDisabledReason = shortcutInfo.mDisabledReason;
            shortcutInfoCompat.mIcon = shortcutInfo.mIcon;
            shortcutInfoCompat.mIsAlwaysBadged = shortcutInfo.mIsAlwaysBadged;
            shortcutInfoCompat.mUser = shortcutInfo.mUser;
            shortcutInfoCompat.mLastChangedTimestamp = shortcutInfo.mLastChangedTimestamp;
            shortcutInfoCompat.mIsCached = shortcutInfo.mIsCached;
            shortcutInfoCompat.mIsDynamic = shortcutInfo.mIsDynamic;
            shortcutInfoCompat.mIsPinned = shortcutInfo.mIsPinned;
            shortcutInfoCompat.mIsDeclaredInManifest = shortcutInfo.mIsDeclaredInManifest;
            shortcutInfoCompat.mIsImmutable = shortcutInfo.mIsImmutable;
            shortcutInfoCompat.mIsEnabled = shortcutInfo.mIsEnabled;
            shortcutInfoCompat.mLocusId = shortcutInfo.mLocusId;
            shortcutInfoCompat.mIsLongLived = shortcutInfo.mIsLongLived;
            shortcutInfoCompat.mHasKeyFieldsOnly = shortcutInfo.mHasKeyFieldsOnly;
            shortcutInfoCompat.mRank = shortcutInfo.mRank;
            if (shortcutInfo.mPersons != null) {
                shortcutInfoCompat.mPersons = (Person[]) Arrays.copyOf(shortcutInfo.mPersons, shortcutInfo.mPersons.length);
            }
            if (shortcutInfo.mCategories != null) {
                shortcutInfoCompat.mCategories = new HashSet(shortcutInfo.mCategories);
            }
            if (shortcutInfo.mExtras != null) {
                shortcutInfoCompat.mExtras = shortcutInfo.mExtras;
            }
        }

        public Builder(Context context, ShortcutInfo shortcutInfo) {
            int i;
            ShortcutInfoCompat shortcutInfoCompat = new ShortcutInfoCompat();
            this.mInfo = shortcutInfoCompat;
            shortcutInfoCompat.mContext = context;
            shortcutInfoCompat.mId = shortcutInfo.getId();
            shortcutInfoCompat.mPackageName = shortcutInfo.getPackage();
            Intent[] intents = shortcutInfo.getIntents();
            shortcutInfoCompat.mIntents = (Intent[]) Arrays.copyOf(intents, intents.length);
            shortcutInfoCompat.mActivity = shortcutInfo.getActivity();
            shortcutInfoCompat.mLabel = shortcutInfo.getShortLabel();
            shortcutInfoCompat.mLongLabel = shortcutInfo.getLongLabel();
            shortcutInfoCompat.mDisabledMessage = shortcutInfo.getDisabledMessage();
            if (Build.VERSION.SDK_INT >= 28) {
                shortcutInfoCompat.mDisabledReason = shortcutInfo.getDisabledReason();
            } else {
                if (shortcutInfo.isEnabled()) {
                    i = 0;
                } else {
                    i = 3;
                }
                shortcutInfoCompat.mDisabledReason = i;
            }
            shortcutInfoCompat.mCategories = shortcutInfo.getCategories();
            shortcutInfoCompat.mPersons = ShortcutInfoCompat.getPersonsFromExtra(shortcutInfo.getExtras());
            shortcutInfoCompat.mUser = shortcutInfo.getUserHandle();
            shortcutInfoCompat.mLastChangedTimestamp = shortcutInfo.getLastChangedTimestamp();
            if (Build.VERSION.SDK_INT >= 30) {
                shortcutInfoCompat.mIsCached = shortcutInfo.isCached();
            }
            shortcutInfoCompat.mIsDynamic = shortcutInfo.isDynamic();
            shortcutInfoCompat.mIsPinned = shortcutInfo.isPinned();
            shortcutInfoCompat.mIsDeclaredInManifest = shortcutInfo.isDeclaredInManifest();
            shortcutInfoCompat.mIsImmutable = shortcutInfo.isImmutable();
            shortcutInfoCompat.mIsEnabled = shortcutInfo.isEnabled();
            shortcutInfoCompat.mHasKeyFieldsOnly = shortcutInfo.hasKeyFieldsOnly();
            shortcutInfoCompat.mLocusId = ShortcutInfoCompat.getLocusId(shortcutInfo);
            shortcutInfoCompat.mRank = shortcutInfo.getRank();
            shortcutInfoCompat.mExtras = shortcutInfo.getExtras();
        }

        public Builder setShortLabel(CharSequence shortLabel) {
            this.mInfo.mLabel = shortLabel;
            return this;
        }

        public Builder setLongLabel(CharSequence longLabel) {
            this.mInfo.mLongLabel = longLabel;
            return this;
        }

        public Builder setDisabledMessage(CharSequence disabledMessage) {
            this.mInfo.mDisabledMessage = disabledMessage;
            return this;
        }

        public Builder setIntent(Intent intent) {
            return setIntents(new Intent[]{intent});
        }

        public Builder setIntents(Intent[] intents) {
            this.mInfo.mIntents = intents;
            return this;
        }

        public Builder setIcon(IconCompat icon) {
            this.mInfo.mIcon = icon;
            return this;
        }

        public Builder setLocusId(LocusIdCompat locusId) {
            this.mInfo.mLocusId = locusId;
            return this;
        }

        public Builder setIsConversation() {
            this.mIsConversation = true;
            return this;
        }

        public Builder setActivity(ComponentName activity) {
            this.mInfo.mActivity = activity;
            return this;
        }

        public Builder setAlwaysBadged() {
            this.mInfo.mIsAlwaysBadged = true;
            return this;
        }

        public Builder setPerson(Person person) {
            return setPersons(new Person[]{person});
        }

        public Builder setPersons(Person[] persons) {
            this.mInfo.mPersons = persons;
            return this;
        }

        public Builder setCategories(Set<String> categories) {
            this.mInfo.mCategories = categories;
            return this;
        }

        @Deprecated
        public Builder setLongLived() {
            this.mInfo.mIsLongLived = true;
            return this;
        }

        public Builder setLongLived(boolean longLived) {
            this.mInfo.mIsLongLived = longLived;
            return this;
        }

        public Builder setRank(int rank) {
            this.mInfo.mRank = rank;
            return this;
        }

        public Builder setExtras(PersistableBundle extras) {
            this.mInfo.mExtras = extras;
            return this;
        }

        public Builder addCapabilityBinding(String capability) {
            if (this.mCapabilityBindings == null) {
                this.mCapabilityBindings = new HashSet();
            }
            this.mCapabilityBindings.add(capability);
            return this;
        }

        public Builder addCapabilityBinding(String capability, String parameter, List<String> parameterValues) {
            addCapabilityBinding(capability);
            if (!parameterValues.isEmpty()) {
                if (this.mCapabilityBindingParams == null) {
                    this.mCapabilityBindingParams = new HashMap();
                }
                if (this.mCapabilityBindingParams.get(capability) == null) {
                    this.mCapabilityBindingParams.put(capability, new HashMap());
                }
                this.mCapabilityBindingParams.get(capability).put(parameter, parameterValues);
            }
            return this;
        }

        public Builder setSliceUri(Uri sliceUri) {
            this.mSliceUri = sliceUri;
            return this;
        }

        public ShortcutInfoCompat build() {
            if (TextUtils.isEmpty(this.mInfo.mLabel)) {
                throw new IllegalArgumentException("Shortcut must have a non-empty label");
            }
            if (this.mInfo.mIntents == null || this.mInfo.mIntents.length == 0) {
                throw new IllegalArgumentException("Shortcut must have an intent");
            }
            if (this.mIsConversation) {
                if (this.mInfo.mLocusId == null) {
                    ShortcutInfoCompat shortcutInfoCompat = this.mInfo;
                    shortcutInfoCompat.mLocusId = new LocusIdCompat(shortcutInfoCompat.mId);
                }
                this.mInfo.mIsLongLived = true;
            }
            if (this.mCapabilityBindings != null) {
                if (this.mInfo.mCategories == null) {
                    this.mInfo.mCategories = new HashSet();
                }
                this.mInfo.mCategories.addAll(this.mCapabilityBindings);
            }
            if (Build.VERSION.SDK_INT >= 21) {
                if (this.mCapabilityBindingParams != null) {
                    if (this.mInfo.mExtras == null) {
                        this.mInfo.mExtras = new PersistableBundle();
                    }
                    for (String capability : this.mCapabilityBindingParams.keySet()) {
                        Map<String, List<String>> params = this.mCapabilityBindingParams.get(capability);
                        Set<String> paramNames = params.keySet();
                        this.mInfo.mExtras.putStringArray(capability, (String[]) paramNames.toArray(new String[0]));
                        for (String paramName : params.keySet()) {
                            List<String> value = params.get(paramName);
                            PersistableBundle persistableBundle = this.mInfo.mExtras;
                            String str = capability + "/" + paramName;
                            String[] strArr = new String[0];
                            if (value != null) {
                                strArr = (String[]) value.toArray(strArr);
                            }
                            persistableBundle.putStringArray(str, strArr);
                        }
                    }
                }
                if (this.mSliceUri != null) {
                    if (this.mInfo.mExtras == null) {
                        this.mInfo.mExtras = new PersistableBundle();
                    }
                    this.mInfo.mExtras.putString(ShortcutInfoCompat.EXTRA_SLICE_URI, UriCompat.toSafeString(this.mSliceUri));
                }
            }
            return this.mInfo;
        }
    }
}
