package androidx.core.content;

import java.util.ArrayList;
/* loaded from: classes.dex */
public final class MimeTypeFilter {
    private MimeTypeFilter() {
    }

    private static boolean mimeTypeAgainstFilter(String[] mimeTypeParts, String[] filterParts) {
        if (filterParts.length != 2) {
            throw new IllegalArgumentException("Ill-formatted MIME type filter. Must be type/subtype.");
        }
        if (filterParts[0].isEmpty() || filterParts[1].isEmpty()) {
            throw new IllegalArgumentException("Ill-formatted MIME type filter. Type or subtype empty.");
        }
        if (mimeTypeParts.length != 2) {
            return false;
        }
        if ("*".equals(filterParts[0]) || filterParts[0].equals(mimeTypeParts[0])) {
            return "*".equals(filterParts[1]) || filterParts[1].equals(mimeTypeParts[1]);
        }
        return false;
    }

    public static boolean matches(String mimeType, String filter) {
        if (mimeType == null) {
            return false;
        }
        String[] mimeTypeParts = mimeType.split("/");
        String[] filterParts = filter.split("/");
        return mimeTypeAgainstFilter(mimeTypeParts, filterParts);
    }

    public static String matches(String mimeType, String[] filters) {
        if (mimeType == null) {
            return null;
        }
        String[] mimeTypeParts = mimeType.split("/");
        for (String filter : filters) {
            String[] filterParts = filter.split("/");
            if (mimeTypeAgainstFilter(mimeTypeParts, filterParts)) {
                return filter;
            }
        }
        return null;
    }

    public static String matches(String[] mimeTypes, String filter) {
        if (mimeTypes == null) {
            return null;
        }
        String[] filterParts = filter.split("/");
        for (String mimeType : mimeTypes) {
            String[] mimeTypeParts = mimeType.split("/");
            if (mimeTypeAgainstFilter(mimeTypeParts, filterParts)) {
                return mimeType;
            }
        }
        return null;
    }

    public static String[] matchesMany(String[] mimeTypes, String filter) {
        if (mimeTypes == null) {
            return new String[0];
        }
        ArrayList<String> list = new ArrayList<>();
        String[] filterParts = filter.split("/");
        for (String mimeType : mimeTypes) {
            String[] mimeTypeParts = mimeType.split("/");
            if (mimeTypeAgainstFilter(mimeTypeParts, filterParts)) {
                list.add(mimeType);
            }
        }
        return (String[]) list.toArray(new String[list.size()]);
    }
}
