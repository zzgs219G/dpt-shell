package com.luoyesiqiu.shell.util;

import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;

import com.luoyesiqiu.shell.Global;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.zip.CRC32;
import java.util.zip.CheckedInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class FileUtils {
    private static final String TAG = "dpt";

    public static void unzipLibs(String sourceDir, String dataDir) {
        String abiName = EnvUtils.getAbiDirName();

        File libsOutDir = new File(dataDir + File.separator + Global.LIB_DIR + File.separator + abiName);

        // ── 把 APK 路径落到 so 旁边，供 native 侧派生链读取 ──────────────
        //
        // 为什么必须由 Java 写：.bitcode 解密跑在 so 的 init_array 里，那时
        // 连 System.loadLibrary 都还没返回，更没有任何 Context。
        // 原实现让 C 自己找 APK，两条路都不成立（2026-10-27 真机实测）：
        //   ① /proc/self/maps 找 base.apk —— init_array 阶段 APK 还没被 mmap，
        //      日志实证 "[keyladder] find apk failed"；
        //   ② so 路径反推 .../lib/<abi>/x.so → base.apk —— 壳 so 实际在
        //      dataDir/dpt-libs/<abi>/，路径里没有 "/lib/"，反推不到。
        // 而 Java 这一层本来就知道 sourceDir（它就是本方法的入参），
        // 写下来是最可靠、零额外成本的做法。
        writeApkPathHint(sourceDir, libsOutDir);
        setApkPathEnv(sourceDir);

        FileUtils.unzipInNeeded(sourceDir,
                "assets/" + Global.ZIP_LIB_DIR + "/" + abiName + "/" + Global.SHELL_SO_NAME,
                libsOutDir.getAbsolutePath());
    }

    /** C 侧读的 APK 路径提示文件名（与 dpt_keyladder.c 的 KL_APK_HINT_NAME 一致）。 */
    private static final String APK_HINT_NAME = "apk-path";

    /**
     * C 侧读的 APK 路径环境变量名（与 dpt_keyladder.c 的 KL_APK_ENV_NAME 一致）。
     *
     * 为什么同时用环境变量而不只用文件：文件写在 {@code dataDir/dpt-libs/<abi>/}，
     * 该目录与 so 同权限域，写与读都受 SELinux/文件模式影响；环境变量在
     * {@code System.load} 之前由本进程 setenv 设置，native 侧 getenv 直读，
     * 不经过文件系统，也不受 0444 只读影响（曾把 hint 文件 chmod 0444，
     * 覆盖安装时写不进去，只能靠 catch 吞掉 —— 那种"看起来写了其实没写"
     * 的静默失败正是最难查的）。两条路都留：环境变量优先，文件兜底。 */
    private static final String APK_ENV_NAME = "DPT_APK_PATH";

    /**
     * 把 APK 绝对路径写到 {@code <libsOutDir>/apk-path}。
     *
     * 失败不抛：拿不到提示时 C 侧仍会退回自己的探测逻辑，最坏是该退包退化为
     * fail-closed（用户看到启动失败），但不应该因为写不了提示就直接崩溃。
     */
    private static void writeApkPathHint(String apkPath, File libsOutDir) {
        if (apkPath == null || apkPath.isEmpty()) {
            return;
        }
        try {
            //noinspection ResultOfMethodCallIgnored
            libsOutDir.mkdirs();
            File hint = new File(libsOutDir, APK_HINT_NAME);
            try (FileOutputStream out = new FileOutputStream(hint)) {
                out.write(apkPath.getBytes("UTF-8"));
                out.write('\n');
            }
            // native 侧只需要可读；与 so 一样保持非写权限，减少被改的机会。
            try {
                Os.chmod(hint.getAbsolutePath(), 0444);
            } catch (ErrnoException ignored) {
            }
        } catch (Throwable e) {
            Log.w(TAG, "write apk path hint failed: " + apkPath, e);
        }
    }

    /**
     * 把 APK 路径写进进程环境变量，供 native 侧 init_array 读取。
     * 必须在 {@code System.load} 之前调用（本类三个调用点都满足）。
     */
    private static void setApkPathEnv(String apkPath) {
        if (apkPath == null || apkPath.isEmpty()) {
            return;
        }
        try {
            Os.setenv(APK_ENV_NAME, apkPath, true);
        } catch (Throwable e) {
            Log.w(TAG, "setenv " + APK_ENV_NAME + " failed", e);
        }
    }

    public static long getCrc32(File f) {
        long crcResult = 0L;
        try (FileInputStream fileInputStream = new FileInputStream(f);
             CheckedInputStream checkedInputStream = new CheckedInputStream(fileInputStream, new CRC32())) {
            byte[] buf = new byte[4096];
            while (checkedInputStream.read(buf) != -1) {
            }
            crcResult = checkedInputStream.getChecksum().getValue();
        }
        catch (Throwable e){
        }
        return crcResult;
    }

    /**
     * Android linker refuses to load writable ELF files (e.g. mode 0600 from FileOutputStream).
     * Keep shell libs read-only, consistent with dex extract chmod(..., 0444).
     */
    static void makeShellLibLoadable(File file) {
        if (file == null || !file.exists()) {
            return;
        }
        try {
            Os.chmod(file.getAbsolutePath(), 0444);
        } catch (ErrnoException e) {
            Log.w(TAG, "chmod shell lib failed: " + file.getAbsolutePath(), e);
            //noinspection ResultOfMethodCallIgnored
            file.setReadable(true, false);
            //noinspection ResultOfMethodCallIgnored
            file.setWritable(false, false);
        }
    }

    public static void unzipInNeeded(String zipFilePath, String entryName, String outDir){
        long start = System.currentTimeMillis();
        File out = new File(outDir);
        if(!out.exists()){
            out.mkdirs();
        }

        long localFileCrc = 0L;
        File entryFile = new File(outDir + File.separator  + Global.SHELL_SO_NAME);
        if(entryFile.exists()){
            localFileCrc = getCrc32(entryFile);
        }
        try (ZipFile zip = new ZipFile(zipFilePath)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while(entries.hasMoreElements()){
                ZipEntry entry = entries.nextElement();

                if(!entry.getName().equals(entryName)) {
                    continue;
                }

                if(localFileCrc != entry.getCrc()) {
                    byte[] buf = new byte[4096];
                    int len = -1;

                    // Previous extract may have left the library read-only.
                    if(entryFile.exists()) {
                        //noinspection ResultOfMethodCallIgnored
                        entryFile.setWritable(true);
                    }

                    try (FileOutputStream fileOutputStream = new FileOutputStream(entryFile);
                         BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
                         BufferedInputStream bufferedInputStream = new BufferedInputStream(zip.getInputStream(entry))) {
                        while ((len = bufferedInputStream.read(buf)) != -1) {
                            bufferedOutputStream.write(buf, 0, len);
                        }
                    }
                    Log.d(TAG, "unzip '" + entry.getName() + "' success. local = " + localFileCrc + ", zip = " + entry.getCrc());
                    break;
                }
                else {
                    Log.w(TAG, "no need unzip");
                }
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        // Always enforce read-only mode so System.load succeeds on Android 14+/HyperOS.
        makeShellLibLoadable(entryFile);
        Log.d(TAG, "unzip libs took: " + (System.currentTimeMillis() - start) + "ms" );
    }

    public static void close(Closeable closeable){
        if(closeable != null){
            try {
                closeable.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

}
