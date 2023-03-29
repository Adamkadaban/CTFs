package androidx.constraintlayout.core.motion.utils;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.Socket;
/* loaded from: classes.dex */
public class Utils {
    static DebugHandle ourHandle;

    /* loaded from: classes.dex */
    public interface DebugHandle {
        void message(String str);
    }

    public static void log(String tag, String value) {
        PrintStream printStream = System.out;
        printStream.println(tag + " : " + value);
    }

    public static void loge(String tag, String value) {
        PrintStream printStream = System.err;
        printStream.println(tag + " : " + value);
    }

    public static void socketSend(String str) {
        try {
            Socket socket = new Socket("127.0.0.1", 5327);
            OutputStream out = socket.getOutputStream();
            out.write(str.getBytes());
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static int clamp(int c) {
        int c2 = (c & (~(c >> 31))) - 255;
        return (c2 & (c2 >> 31)) + 255;
    }

    public int getInterpolatedColor(float[] value) {
        int r = clamp((int) (((float) Math.pow(value[0], 0.45454545454545453d)) * 255.0f));
        int g = clamp((int) (((float) Math.pow(value[1], 0.45454545454545453d)) * 255.0f));
        int b = clamp((int) (((float) Math.pow(value[2], 0.45454545454545453d)) * 255.0f));
        int a = clamp((int) (value[3] * 255.0f));
        int color = (a << 24) | (r << 16) | (g << 8) | b;
        return color;
    }

    public static int rgbaTocColor(float r, float g, float b, float a) {
        int ir = clamp((int) (r * 255.0f));
        int ig = clamp((int) (g * 255.0f));
        int ib = clamp((int) (b * 255.0f));
        int ia = clamp((int) (255.0f * a));
        int color = (ia << 24) | (ir << 16) | (ig << 8) | ib;
        return color;
    }

    public static void setDebugHandle(DebugHandle handle) {
        ourHandle = handle;
    }

    public static void logStack(String msg, int n) {
        StackTraceElement[] st = new Throwable().getStackTrace();
        String s = " ";
        int n2 = Math.min(n, st.length - 1);
        for (int i = 1; i <= n2; i++) {
            StackTraceElement stackTraceElement = st[i];
            String stack = ".(" + st[i].getFileName() + ":" + st[i].getLineNumber() + ") " + st[i].getMethodName();
            s = s + " ";
            System.out.println(msg + s + stack + s);
        }
    }

    public static void log(String str) {
        StackTraceElement s = new Throwable().getStackTrace()[1];
        String methodName = s.getMethodName();
        String methodName2 = (methodName + "                  ").substring(0, 17);
        String npad = "    ".substring(Integer.toString(s.getLineNumber()).length());
        String ss = ".(" + s.getFileName() + ":" + s.getLineNumber() + ")" + npad + methodName2;
        System.out.println(ss + " " + str);
        DebugHandle debugHandle = ourHandle;
        if (debugHandle != null) {
            debugHandle.message(ss + " " + str);
        }
    }
}
