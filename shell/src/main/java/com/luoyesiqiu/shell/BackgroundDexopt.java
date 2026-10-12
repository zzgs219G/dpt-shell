package com.luoyesiqiu.shell;

import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 后台分级 dexopt（报错四十五，方案：apk-protect-action/docs/后台dexopt方案.md）。
 *
 * <p>背景：加壳包的装包期 dexopt 看不到业务 dex（它运行时才解密落盘），系统因
 * baseline profile 失配把编译档位降为 verify（装包日志实锤：{@code no valid
 * profile}）——每次冷启动都要现场做约 1,660 次 VerifyClass + 全程解释执行
 * （trace 实测主线程 Running +227ms，见 docs/atrace启动轨迹归因报告.md）。
 *
 * <p>本类在解密落盘之后（attachBaseContext 后 ~5s，后台线程）调用系统编译器
 * dex2oat，对落盘的 xixin_dexes.zip 做一次 quicken 档编译，产物 odex 放
 * ART 的标准查找位置（code_cache/oat/<isa>/xixin_dexes.odex）。之后的冷启动：
 * <ul>
 *   <li>校验和匹配 → 跳过 VerifyClass（校验信息已在 odex 中）；</li>
 *   <li>quicken 产物含快速化指令 → 解释执行更省。</li>
 * </ul>
 *
 * <p>幂等：marker（zip 的 sha1 指纹）与当前 zip 一致且 odex 存在 → 跳过。
 * App 升级 → 指纹变化 → 自动重编一次。
 *
 * <p>失败兜底：任何异常静默放弃——最坏回到现状（每次启动现场校验），不劣化。
 * 仅磁盘模式有意义（内存模式无落盘文件，zip 不存在自然跳过）。
 */
public final class BackgroundDexopt {
    private static final String TAG = "dpt_bgdx";
    /** 与 native 侧 DEXES_ZIP_NAME（common/dpt_macro.h）一致。 */
    static final String DEXES_ZIP_NAME = "xixin_dexes.zip";
    static final String MARKER_SUFFIX = ".sha1";
    /** dex2oat 单次运行的超时上限（超时 kill，视为失败）。 */
    private static final long TIMEOUT_SECONDS = 60;

    /** dex2oat 候选路径，按优先级探测（ART APEX 优先，旧版本兜底）。 */
    static final String[] DEX2OAT_CANDIDATES = {
            "/apex/com.android.art/bin/dex2oat64",
            "/apex/com.android.art/bin/dex2oat",
            "/system/bin/dex2oat64",
            "/system/bin/dex2oat",
    };

    private BackgroundDexopt() {}

    /**
     * 调度入口：后台线程延迟 {@code delayMs} 后执行。任何异常吞掉——
     * 本功能失败只意味着回到现状，不允许影响启动。
     */
    public static void schedule(final String codeCacheDir, final String isa, final long delayMs) {
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException ignored) {
                return;
            }
            try {
                run(codeCacheDir, isa, pickDex2oat());
            } catch (Throwable t1) {
                Log.w(TAG, "background dexopt skipped: " + t1);
            }
        }, "dpt-bg-dexopt");
        t.setDaemon(true);
        t.start();
    }

    /** 执行一次「检查 + 编译」；dex2oatBin 为 null 时走路径探测。包级可见便于测试。 */
    static void run(String codeCacheDir, String isa, String dex2oatBin) throws Exception {
        File zip = new File(codeCacheDir, DEXES_ZIP_NAME);
        if (!zip.isFile()) {
            Log.i(TAG, "dex zip not found, skip");
            return;
        }
        File oatDir = new File(new File(codeCacheDir, "oat"), isa);
        File odex = new File(oatDir, "xixin_dexes.odex");
        File marker = new File(codeCacheDir, DEXES_ZIP_NAME + MARKER_SUFFIX);

        String sha1 = sha1Hex(zip);
        String markerSha = marker.isFile() ? readAll(marker) : "";
        if (odex.isFile() && markerSha.equals(sha1)) {
            Log.i(TAG, "odex up-to-date, skip");
            return;
        }

        String bin = dex2oatBin != null ? dex2oatBin : pickDex2oat();
        if (bin == null) {
            Log.i(TAG, "dex2oat not found, skip");
            return;
        }

        if (!oatDir.isDirectory() && !oatDir.mkdirs()) {
            Log.w(TAG, "cannot create oat dir: " + oatDir);
            return;
        }

        List<String> cmd = buildCommand(bin, zip.getAbsolutePath(), odex.getAbsolutePath(), isa);
        int rc = exec(cmd, TIMEOUT_SECONDS);
        Log.i(TAG, "dex2oat rc=" + rc + " (" + isa + ")");
        if (rc == 0) {
            writeAll(marker, sha1);
        } else {
            // 失败：清掉半成品，避免残留（ART 本会忽略失配产物，删除只是整洁）
            odex.delete();
        }
    }

    /** 组装 dex2oat 命令行（单测锁定）。 */
    static List<String> buildCommand(String dex2oatBin, String dexPath, String oatPath, String isa) {
        List<String> cmd = new ArrayList<>();
        cmd.add(dex2oatBin);
        cmd.add("--dex-file=" + dexPath);
        cmd.add("--oat-file=" + oatPath);
        cmd.add("--compiler-filter=quicken");
        cmd.add("--instruction-set=" + isa);
        return cmd;
    }

    /** 按 DEX2OAT_CANDIDATES 顺序探测第一个可执行文件。 */
    static String pickDex2oat() {
        for (String c : DEX2OAT_CANDIDATES) {
            File f = new File(c);
            if (f.isFile() && f.canExecute()) return c;
        }
        return null;
    }

    private static int exec(List<String> cmd, long timeoutSeconds)
            throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        // 消费输出防管道写满阻塞（dex2oat 的输出量不小）
        InputStream out = p.getInputStream();
        byte[] buf = new byte[4096];
        while (out.read(buf) != -1) { /* 丢弃 */ }
        boolean done = p.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        if (!done) {
            p.destroy();
            return -1;
        }
        return p.exitValue();
    }

    static String sha1Hex(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        try (InputStream in = new FileInputStream(f)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                md.update(buf, 0, n);
            }
        }
        StringBuilder sb = new StringBuilder(40);
        for (byte b : md.digest()) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static String readAll(File f) throws IOException {
        try (InputStream in = new FileInputStream(f)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[512];
            int n;
            while ((n = in.read(buf)) != -1) {
                bos.write(buf, 0, n);
            }
            return new String(bos.toByteArray(), "UTF-8").trim();
        }
    }

    private static void writeAll(File f, String content) throws IOException {
        try (OutputStream out = new FileOutputStream(f)) {
            out.write(content.getBytes("UTF-8"));
        }
    }
}
