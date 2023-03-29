package androidx.core.app;

import android.app.AppOpsManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationChannelGroup;
import android.app.NotificationManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ApplicationInfo;
import android.content.pm.ResolveInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.DeadObjectException;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Message;
import android.os.RemoteException;
import android.provider.Settings;
import android.support.v4.app.INotificationSideChannel;
import android.util.Log;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
/* loaded from: classes.dex */
public final class NotificationManagerCompat {
    public static final String ACTION_BIND_SIDE_CHANNEL = "android.support.BIND_NOTIFICATION_SIDE_CHANNEL";
    private static final String CHECK_OP_NO_THROW = "checkOpNoThrow";
    public static final String EXTRA_USE_SIDE_CHANNEL = "android.support.useSideChannel";
    public static final int IMPORTANCE_DEFAULT = 3;
    public static final int IMPORTANCE_HIGH = 4;
    public static final int IMPORTANCE_LOW = 2;
    public static final int IMPORTANCE_MAX = 5;
    public static final int IMPORTANCE_MIN = 1;
    public static final int IMPORTANCE_NONE = 0;
    public static final int IMPORTANCE_UNSPECIFIED = -1000;
    static final int MAX_SIDE_CHANNEL_SDK_VERSION = 19;
    private static final String OP_POST_NOTIFICATION = "OP_POST_NOTIFICATION";
    private static final String SETTING_ENABLED_NOTIFICATION_LISTENERS = "enabled_notification_listeners";
    private static final int SIDE_CHANNEL_RETRY_BASE_INTERVAL_MS = 1000;
    private static final int SIDE_CHANNEL_RETRY_MAX_COUNT = 6;
    private static final String TAG = "NotifManCompat";
    private static String sEnabledNotificationListeners;
    private static SideChannelManager sSideChannelManager;
    private final Context mContext;
    private final NotificationManager mNotificationManager;
    private static final Object sEnabledNotificationListenersLock = new Object();
    private static Set<String> sEnabledNotificationListenerPackages = new HashSet();
    private static final Object sLock = new Object();

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public interface Task {
        void send(INotificationSideChannel iNotificationSideChannel) throws RemoteException;
    }

    public static NotificationManagerCompat from(Context context) {
        return new NotificationManagerCompat(context);
    }

    private NotificationManagerCompat(Context context) {
        this.mContext = context;
        this.mNotificationManager = (NotificationManager) context.getSystemService("notification");
    }

    public void cancel(int id) {
        cancel(null, id);
    }

    public void cancel(String tag, int id) {
        this.mNotificationManager.cancel(tag, id);
        if (Build.VERSION.SDK_INT <= 19) {
            pushSideChannelQueue(new CancelTask(this.mContext.getPackageName(), id, tag));
        }
    }

    public void cancelAll() {
        this.mNotificationManager.cancelAll();
        if (Build.VERSION.SDK_INT <= 19) {
            pushSideChannelQueue(new CancelTask(this.mContext.getPackageName()));
        }
    }

    public void notify(int id, Notification notification) {
        notify(null, id, notification);
    }

    public void notify(String tag, int id, Notification notification) {
        if (useSideChannelForNotification(notification)) {
            pushSideChannelQueue(new NotifyTask(this.mContext.getPackageName(), id, tag, notification));
            this.mNotificationManager.cancel(tag, id);
            return;
        }
        this.mNotificationManager.notify(tag, id, notification);
    }

    public boolean areNotificationsEnabled() {
        if (Build.VERSION.SDK_INT >= 24) {
            return this.mNotificationManager.areNotificationsEnabled();
        }
        if (Build.VERSION.SDK_INT >= 19) {
            AppOpsManager appOps = (AppOpsManager) this.mContext.getSystemService("appops");
            ApplicationInfo appInfo = this.mContext.getApplicationInfo();
            String pkg = this.mContext.getApplicationContext().getPackageName();
            int uid = appInfo.uid;
            try {
                Class<?> appOpsClass = Class.forName(AppOpsManager.class.getName());
                Method checkOpNoThrowMethod = appOpsClass.getMethod(CHECK_OP_NO_THROW, Integer.TYPE, Integer.TYPE, String.class);
                Field opPostNotificationValue = appOpsClass.getDeclaredField(OP_POST_NOTIFICATION);
                int value = ((Integer) opPostNotificationValue.get(Integer.class)).intValue();
                return ((Integer) checkOpNoThrowMethod.invoke(appOps, Integer.valueOf(value), Integer.valueOf(uid), pkg)).intValue() == 0;
            } catch (ClassNotFoundException | IllegalAccessException | NoSuchFieldException | NoSuchMethodException | RuntimeException | InvocationTargetException e) {
                return true;
            }
        }
        return true;
    }

    public int getImportance() {
        if (Build.VERSION.SDK_INT >= 24) {
            return this.mNotificationManager.getImportance();
        }
        return IMPORTANCE_UNSPECIFIED;
    }

    public void createNotificationChannel(NotificationChannel channel) {
        if (Build.VERSION.SDK_INT >= 26) {
            this.mNotificationManager.createNotificationChannel(channel);
        }
    }

    public void createNotificationChannel(NotificationChannelCompat channel) {
        createNotificationChannel(channel.getNotificationChannel());
    }

    public void createNotificationChannelGroup(NotificationChannelGroup group) {
        if (Build.VERSION.SDK_INT >= 26) {
            this.mNotificationManager.createNotificationChannelGroup(group);
        }
    }

    public void createNotificationChannelGroup(NotificationChannelGroupCompat group) {
        createNotificationChannelGroup(group.getNotificationChannelGroup());
    }

    public void createNotificationChannels(List<NotificationChannel> channels) {
        if (Build.VERSION.SDK_INT >= 26) {
            this.mNotificationManager.createNotificationChannels(channels);
        }
    }

    public void createNotificationChannelsCompat(List<NotificationChannelCompat> channels) {
        if (Build.VERSION.SDK_INT >= 26 && !channels.isEmpty()) {
            List<NotificationChannel> platformChannels = new ArrayList<>(channels.size());
            for (NotificationChannelCompat channel : channels) {
                platformChannels.add(channel.getNotificationChannel());
            }
            this.mNotificationManager.createNotificationChannels(platformChannels);
        }
    }

    public void createNotificationChannelGroups(List<NotificationChannelGroup> groups) {
        if (Build.VERSION.SDK_INT >= 26) {
            this.mNotificationManager.createNotificationChannelGroups(groups);
        }
    }

    public void createNotificationChannelGroupsCompat(List<NotificationChannelGroupCompat> groups) {
        if (Build.VERSION.SDK_INT >= 26 && !groups.isEmpty()) {
            List<NotificationChannelGroup> platformGroups = new ArrayList<>(groups.size());
            for (NotificationChannelGroupCompat group : groups) {
                platformGroups.add(group.getNotificationChannelGroup());
            }
            this.mNotificationManager.createNotificationChannelGroups(platformGroups);
        }
    }

    public void deleteNotificationChannel(String channelId) {
        if (Build.VERSION.SDK_INT >= 26) {
            this.mNotificationManager.deleteNotificationChannel(channelId);
        }
    }

    public void deleteNotificationChannelGroup(String groupId) {
        if (Build.VERSION.SDK_INT >= 26) {
            this.mNotificationManager.deleteNotificationChannelGroup(groupId);
        }
    }

    public void deleteUnlistedNotificationChannels(Collection<String> channelIds) {
        if (Build.VERSION.SDK_INT >= 26) {
            for (NotificationChannel channel : this.mNotificationManager.getNotificationChannels()) {
                if (!channelIds.contains(channel.getId()) && (Build.VERSION.SDK_INT < 30 || !channelIds.contains(channel.getParentChannelId()))) {
                    this.mNotificationManager.deleteNotificationChannel(channel.getId());
                }
            }
        }
    }

    public NotificationChannel getNotificationChannel(String channelId) {
        if (Build.VERSION.SDK_INT >= 26) {
            return this.mNotificationManager.getNotificationChannel(channelId);
        }
        return null;
    }

    public NotificationChannelCompat getNotificationChannelCompat(String channelId) {
        NotificationChannel channel;
        if (Build.VERSION.SDK_INT >= 26 && (channel = getNotificationChannel(channelId)) != null) {
            return new NotificationChannelCompat(channel);
        }
        return null;
    }

    public NotificationChannel getNotificationChannel(String channelId, String conversationId) {
        if (Build.VERSION.SDK_INT >= 30) {
            return this.mNotificationManager.getNotificationChannel(channelId, conversationId);
        }
        return getNotificationChannel(channelId);
    }

    public NotificationChannelCompat getNotificationChannelCompat(String channelId, String conversationId) {
        NotificationChannel channel;
        if (Build.VERSION.SDK_INT >= 26 && (channel = getNotificationChannel(channelId, conversationId)) != null) {
            return new NotificationChannelCompat(channel);
        }
        return null;
    }

    public NotificationChannelGroup getNotificationChannelGroup(String channelGroupId) {
        if (Build.VERSION.SDK_INT >= 28) {
            return this.mNotificationManager.getNotificationChannelGroup(channelGroupId);
        }
        if (Build.VERSION.SDK_INT >= 26) {
            for (NotificationChannelGroup group : getNotificationChannelGroups()) {
                if (group.getId().equals(channelGroupId)) {
                    return group;
                }
            }
            return null;
        }
        return null;
    }

    public NotificationChannelGroupCompat getNotificationChannelGroupCompat(String channelGroupId) {
        NotificationChannelGroup group;
        if (Build.VERSION.SDK_INT >= 28) {
            NotificationChannelGroup group2 = getNotificationChannelGroup(channelGroupId);
            if (group2 != null) {
                return new NotificationChannelGroupCompat(group2);
            }
            return null;
        } else if (Build.VERSION.SDK_INT >= 26 && (group = getNotificationChannelGroup(channelGroupId)) != null) {
            return new NotificationChannelGroupCompat(group, getNotificationChannels());
        } else {
            return null;
        }
    }

    public List<NotificationChannel> getNotificationChannels() {
        if (Build.VERSION.SDK_INT >= 26) {
            return this.mNotificationManager.getNotificationChannels();
        }
        return Collections.emptyList();
    }

    public List<NotificationChannelCompat> getNotificationChannelsCompat() {
        if (Build.VERSION.SDK_INT >= 26) {
            List<NotificationChannel> channels = getNotificationChannels();
            if (!channels.isEmpty()) {
                List<NotificationChannelCompat> channelsCompat = new ArrayList<>(channels.size());
                for (NotificationChannel channel : channels) {
                    channelsCompat.add(new NotificationChannelCompat(channel));
                }
                return channelsCompat;
            }
        }
        return Collections.emptyList();
    }

    public List<NotificationChannelGroup> getNotificationChannelGroups() {
        if (Build.VERSION.SDK_INT >= 26) {
            return this.mNotificationManager.getNotificationChannelGroups();
        }
        return Collections.emptyList();
    }

    public List<NotificationChannelGroupCompat> getNotificationChannelGroupsCompat() {
        List<NotificationChannel> allChannels;
        if (Build.VERSION.SDK_INT >= 26) {
            List<NotificationChannelGroup> groups = getNotificationChannelGroups();
            if (!groups.isEmpty()) {
                if (Build.VERSION.SDK_INT >= 28) {
                    allChannels = Collections.emptyList();
                } else {
                    allChannels = getNotificationChannels();
                }
                List<NotificationChannelGroupCompat> groupsCompat = new ArrayList<>(groups.size());
                for (NotificationChannelGroup group : groups) {
                    if (Build.VERSION.SDK_INT >= 28) {
                        groupsCompat.add(new NotificationChannelGroupCompat(group));
                    } else {
                        groupsCompat.add(new NotificationChannelGroupCompat(group, allChannels));
                    }
                }
                return groupsCompat;
            }
        }
        return Collections.emptyList();
    }

    public static Set<String> getEnabledListenerPackages(Context context) {
        Set<String> set;
        String enabledNotificationListeners = Settings.Secure.getString(context.getContentResolver(), SETTING_ENABLED_NOTIFICATION_LISTENERS);
        synchronized (sEnabledNotificationListenersLock) {
            if (enabledNotificationListeners != null) {
                if (!enabledNotificationListeners.equals(sEnabledNotificationListeners)) {
                    String[] components = enabledNotificationListeners.split(":", -1);
                    Set<String> packageNames = new HashSet<>(components.length);
                    for (String component : components) {
                        ComponentName componentName = ComponentName.unflattenFromString(component);
                        if (componentName != null) {
                            packageNames.add(componentName.getPackageName());
                        }
                    }
                    sEnabledNotificationListenerPackages = packageNames;
                    sEnabledNotificationListeners = enabledNotificationListeners;
                }
            }
            set = sEnabledNotificationListenerPackages;
        }
        return set;
    }

    private static boolean useSideChannelForNotification(Notification notification) {
        Bundle extras = NotificationCompat.getExtras(notification);
        return extras != null && extras.getBoolean(EXTRA_USE_SIDE_CHANNEL);
    }

    private void pushSideChannelQueue(Task task) {
        synchronized (sLock) {
            if (sSideChannelManager == null) {
                sSideChannelManager = new SideChannelManager(this.mContext.getApplicationContext());
            }
            sSideChannelManager.queueTask(task);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class SideChannelManager implements Handler.Callback, ServiceConnection {
        private static final int MSG_QUEUE_TASK = 0;
        private static final int MSG_RETRY_LISTENER_QUEUE = 3;
        private static final int MSG_SERVICE_CONNECTED = 1;
        private static final int MSG_SERVICE_DISCONNECTED = 2;
        private final Context mContext;
        private final Handler mHandler;
        private final HandlerThread mHandlerThread;
        private final Map<ComponentName, ListenerRecord> mRecordMap = new HashMap();
        private Set<String> mCachedEnabledPackages = new HashSet();

        SideChannelManager(Context context) {
            this.mContext = context;
            HandlerThread handlerThread = new HandlerThread("NotificationManagerCompat");
            this.mHandlerThread = handlerThread;
            handlerThread.start();
            this.mHandler = new Handler(handlerThread.getLooper(), this);
        }

        public void queueTask(Task task) {
            this.mHandler.obtainMessage(0, task).sendToTarget();
        }

        @Override // android.os.Handler.Callback
        public boolean handleMessage(Message msg) {
            switch (msg.what) {
                case 0:
                    handleQueueTask((Task) msg.obj);
                    return true;
                case 1:
                    ServiceConnectedEvent event = (ServiceConnectedEvent) msg.obj;
                    handleServiceConnected(event.componentName, event.iBinder);
                    return true;
                case 2:
                    handleServiceDisconnected((ComponentName) msg.obj);
                    return true;
                case 3:
                    handleRetryListenerQueue((ComponentName) msg.obj);
                    return true;
                default:
                    return false;
            }
        }

        private void handleQueueTask(Task task) {
            updateListenerMap();
            for (ListenerRecord record : this.mRecordMap.values()) {
                record.taskQueue.add(task);
                processListenerQueue(record);
            }
        }

        private void handleServiceConnected(ComponentName componentName, IBinder iBinder) {
            ListenerRecord record = this.mRecordMap.get(componentName);
            if (record != null) {
                record.service = INotificationSideChannel.Stub.asInterface(iBinder);
                record.retryCount = 0;
                processListenerQueue(record);
            }
        }

        private void handleServiceDisconnected(ComponentName componentName) {
            ListenerRecord record = this.mRecordMap.get(componentName);
            if (record != null) {
                ensureServiceUnbound(record);
            }
        }

        private void handleRetryListenerQueue(ComponentName componentName) {
            ListenerRecord record = this.mRecordMap.get(componentName);
            if (record != null) {
                processListenerQueue(record);
            }
        }

        @Override // android.content.ServiceConnection
        public void onServiceConnected(ComponentName componentName, IBinder iBinder) {
            if (Log.isLoggable(NotificationManagerCompat.TAG, 3)) {
                Log.d(NotificationManagerCompat.TAG, "Connected to service " + componentName);
            }
            this.mHandler.obtainMessage(1, new ServiceConnectedEvent(componentName, iBinder)).sendToTarget();
        }

        @Override // android.content.ServiceConnection
        public void onServiceDisconnected(ComponentName componentName) {
            if (Log.isLoggable(NotificationManagerCompat.TAG, 3)) {
                Log.d(NotificationManagerCompat.TAG, "Disconnected from service " + componentName);
            }
            this.mHandler.obtainMessage(2, componentName).sendToTarget();
        }

        private void updateListenerMap() {
            Set<String> enabledPackages = NotificationManagerCompat.getEnabledListenerPackages(this.mContext);
            if (enabledPackages.equals(this.mCachedEnabledPackages)) {
                return;
            }
            this.mCachedEnabledPackages = enabledPackages;
            List<ResolveInfo> resolveInfos = this.mContext.getPackageManager().queryIntentServices(new Intent().setAction(NotificationManagerCompat.ACTION_BIND_SIDE_CHANNEL), 0);
            Set<ComponentName> enabledComponents = new HashSet<>();
            for (ResolveInfo resolveInfo : resolveInfos) {
                if (enabledPackages.contains(resolveInfo.serviceInfo.packageName)) {
                    ComponentName componentName = new ComponentName(resolveInfo.serviceInfo.packageName, resolveInfo.serviceInfo.name);
                    if (resolveInfo.serviceInfo.permission != null) {
                        Log.w(NotificationManagerCompat.TAG, "Permission present on component " + componentName + ", not adding listener record.");
                    } else {
                        enabledComponents.add(componentName);
                    }
                }
            }
            for (ComponentName componentName2 : enabledComponents) {
                if (!this.mRecordMap.containsKey(componentName2)) {
                    if (Log.isLoggable(NotificationManagerCompat.TAG, 3)) {
                        Log.d(NotificationManagerCompat.TAG, "Adding listener record for " + componentName2);
                    }
                    this.mRecordMap.put(componentName2, new ListenerRecord(componentName2));
                }
            }
            Iterator<Map.Entry<ComponentName, ListenerRecord>> it = this.mRecordMap.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<ComponentName, ListenerRecord> entry = it.next();
                if (!enabledComponents.contains(entry.getKey())) {
                    if (Log.isLoggable(NotificationManagerCompat.TAG, 3)) {
                        Log.d(NotificationManagerCompat.TAG, "Removing listener record for " + entry.getKey());
                    }
                    ensureServiceUnbound(entry.getValue());
                    it.remove();
                }
            }
        }

        private boolean ensureServiceBound(ListenerRecord record) {
            if (record.bound) {
                return true;
            }
            Intent intent = new Intent(NotificationManagerCompat.ACTION_BIND_SIDE_CHANNEL).setComponent(record.componentName);
            record.bound = this.mContext.bindService(intent, this, 33);
            if (record.bound) {
                record.retryCount = 0;
            } else {
                Log.w(NotificationManagerCompat.TAG, "Unable to bind to listener " + record.componentName);
                this.mContext.unbindService(this);
            }
            return record.bound;
        }

        private void ensureServiceUnbound(ListenerRecord record) {
            if (record.bound) {
                this.mContext.unbindService(this);
                record.bound = false;
            }
            record.service = null;
        }

        private void scheduleListenerRetry(ListenerRecord record) {
            if (this.mHandler.hasMessages(3, record.componentName)) {
                return;
            }
            record.retryCount++;
            if (record.retryCount > 6) {
                Log.w(NotificationManagerCompat.TAG, "Giving up on delivering " + record.taskQueue.size() + " tasks to " + record.componentName + " after " + record.retryCount + " retries");
                record.taskQueue.clear();
                return;
            }
            int delayMs = (1 << (record.retryCount - 1)) * 1000;
            if (Log.isLoggable(NotificationManagerCompat.TAG, 3)) {
                Log.d(NotificationManagerCompat.TAG, "Scheduling retry for " + delayMs + " ms");
            }
            Message msg = this.mHandler.obtainMessage(3, record.componentName);
            this.mHandler.sendMessageDelayed(msg, delayMs);
        }

        private void processListenerQueue(ListenerRecord record) {
            if (Log.isLoggable(NotificationManagerCompat.TAG, 3)) {
                Log.d(NotificationManagerCompat.TAG, "Processing component " + record.componentName + ", " + record.taskQueue.size() + " queued tasks");
            }
            if (record.taskQueue.isEmpty()) {
                return;
            }
            if (!ensureServiceBound(record) || record.service == null) {
                scheduleListenerRetry(record);
                return;
            }
            while (true) {
                Task task = record.taskQueue.peek();
                if (task == null) {
                    break;
                }
                try {
                    if (Log.isLoggable(NotificationManagerCompat.TAG, 3)) {
                        Log.d(NotificationManagerCompat.TAG, "Sending task " + task);
                    }
                    task.send(record.service);
                    record.taskQueue.remove();
                } catch (DeadObjectException e) {
                    if (Log.isLoggable(NotificationManagerCompat.TAG, 3)) {
                        Log.d(NotificationManagerCompat.TAG, "Remote service has died: " + record.componentName);
                    }
                } catch (RemoteException e2) {
                    Log.w(NotificationManagerCompat.TAG, "RemoteException communicating with " + record.componentName, e2);
                }
            }
            if (!record.taskQueue.isEmpty()) {
                scheduleListenerRetry(record);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* loaded from: classes.dex */
        public static class ListenerRecord {
            final ComponentName componentName;
            INotificationSideChannel service;
            boolean bound = false;
            ArrayDeque<Task> taskQueue = new ArrayDeque<>();
            int retryCount = 0;

            ListenerRecord(ComponentName componentName) {
                this.componentName = componentName;
            }
        }
    }

    /* loaded from: classes.dex */
    private static class ServiceConnectedEvent {
        final ComponentName componentName;
        final IBinder iBinder;

        ServiceConnectedEvent(ComponentName componentName, IBinder iBinder) {
            this.componentName = componentName;
            this.iBinder = iBinder;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class NotifyTask implements Task {
        final int id;
        final Notification notif;
        final String packageName;
        final String tag;

        NotifyTask(String packageName, int id, String tag, Notification notif) {
            this.packageName = packageName;
            this.id = id;
            this.tag = tag;
            this.notif = notif;
        }

        @Override // androidx.core.app.NotificationManagerCompat.Task
        public void send(INotificationSideChannel service) throws RemoteException {
            service.notify(this.packageName, this.id, this.tag, this.notif);
        }

        public String toString() {
            return "NotifyTask[packageName:" + this.packageName + ", id:" + this.id + ", tag:" + this.tag + "]";
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class CancelTask implements Task {
        final boolean all;
        final int id;
        final String packageName;
        final String tag;

        CancelTask(String packageName) {
            this.packageName = packageName;
            this.id = 0;
            this.tag = null;
            this.all = true;
        }

        CancelTask(String packageName, int id, String tag) {
            this.packageName = packageName;
            this.id = id;
            this.tag = tag;
            this.all = false;
        }

        @Override // androidx.core.app.NotificationManagerCompat.Task
        public void send(INotificationSideChannel service) throws RemoteException {
            if (this.all) {
                service.cancelAll(this.packageName);
            } else {
                service.cancel(this.packageName, this.id, this.tag);
            }
        }

        public String toString() {
            return "CancelTask[packageName:" + this.packageName + ", id:" + this.id + ", tag:" + this.tag + ", all:" + this.all + "]";
        }
    }
}
