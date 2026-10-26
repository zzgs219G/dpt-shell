package com.luoyesiqiu.shell;

import android.content.Context;
import android.util.Log;

import androidx.annotation.Keep;

import com.luoyesiqiu.shell.util.EnvUtils;

import java.io.File;

/**
 * Created by luoyesiqiu
 */
@Keep
public class JniBridge {
    private static final String TAG = "dpt_" + JniBridge.class.getSimpleName();
    public static native void craoc(String applicationClassName);
    public static native void ia();
    public static native String rcf();
    public static native void cbde(ClassLoader targetClassLoader);
    public static native void rde(ClassLoader classLoader,String elementName);
    public static native String gap();
    public static native String gdp();
    public static native Object ra(String originApplicationClassName);
    public static native String rapn();
    public static native void clinit();
    /* 字符串解密桩的密钥流种子（packer 联动）。
     *
     * 谁调：stringenc 注入的桩类 <clinit> —— `SEED = JniBridge.gseed()`。
     * 为什么由壳提供：桩合并进壳 dex、4 个算法方法 native 化之后，SEED 若仍是
     *   dex 字面量，脱壳者读壳 dex 就拿到密钥。改为从这里取 = 删壳即拿不到，
     *   App 崩（NoClassDefFoundError）—— 这才是"必须带着壳运行"的联动。
     *
     * ⚠️ 这个声明必须与 C 侧 gMethods[] 里的 {"gseed", "()J", ...} 一一对应：
     *   RegisterNatives 会按类里【实际声明的 native 方法】注册，缺这个声明
     *   就是 "Failed to register native method ... gseed()J" +
     *   NoSuchMethodError（真机实测踩过）。 */
    public static native long gseed();

    public static void loadShellLibs(String workspacePath) {
        final String[] allowLibNames = {Global.SHELL_SO_NAME};
        try {
            String abiDirName = EnvUtils.getAbiDirName();
            File shellLibsFile = new File(workspacePath + File.separator + Global.LIB_DIR + File.separator + abiDirName);
            File[] files = shellLibsFile.listFiles();
            if(files != null) {
                for(File shellLibPath : files) {
                    String fullLibPath = shellLibPath.getAbsolutePath();
                    for(String libName : allowLibNames) {
                        String libSuffix = File.separator + libName;
                        if(fullLibPath.endsWith(libSuffix)) {
                            Log.d(TAG, "loadShellLibs: " + fullLibPath);
                            System.load(fullLibPath);
                        }
                    }
                }
            }
        }
        catch (Throwable e){
            Log.w(TAG,e);
        }
    }

}
