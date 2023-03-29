package androidx.constraintlayout.core.state;

import java.util.HashMap;
import java.util.Set;
/* loaded from: classes.dex */
public class Registry {
    private static final Registry sRegistry = new Registry();
    private HashMap<String, RegistryCallback> mCallbacks = new HashMap<>();

    public static Registry getInstance() {
        return sRegistry;
    }

    public void register(String name, RegistryCallback callback) {
        this.mCallbacks.put(name, callback);
    }

    public void unregister(String name, RegistryCallback callback) {
        this.mCallbacks.remove(name);
    }

    public void updateContent(String name, String content) {
        RegistryCallback callback = this.mCallbacks.get(name);
        if (callback != null) {
            callback.onNewMotionScene(content);
        }
    }

    public void updateProgress(String name, float progress) {
        RegistryCallback callback = this.mCallbacks.get(name);
        if (callback != null) {
            callback.onProgress(progress);
        }
    }

    public String currentContent(String name) {
        RegistryCallback callback = this.mCallbacks.get(name);
        if (callback != null) {
            return callback.currentMotionScene();
        }
        return null;
    }

    public String currentLayoutInformation(String name) {
        RegistryCallback callback = this.mCallbacks.get(name);
        if (callback != null) {
            return callback.currentLayoutInformation();
        }
        return null;
    }

    public void setDrawDebug(String name, int debugMode) {
        RegistryCallback callback = this.mCallbacks.get(name);
        if (callback != null) {
            callback.setDrawDebug(debugMode);
        }
    }

    public void setLayoutInformationMode(String name, int mode) {
        RegistryCallback callback = this.mCallbacks.get(name);
        if (callback != null) {
            callback.setLayoutInformationMode(mode);
        }
    }

    public Set<String> getLayoutList() {
        return this.mCallbacks.keySet();
    }

    public long getLastModified(String name) {
        RegistryCallback callback = this.mCallbacks.get(name);
        if (callback != null) {
            return callback.getLastModified();
        }
        return Long.MAX_VALUE;
    }

    public void updateDimensions(String name, int width, int height) {
        RegistryCallback callback = this.mCallbacks.get(name);
        if (callback != null) {
            callback.onDimensions(width, height);
        }
    }
}
