package com.luoyesiqiu.shell;

import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

/**
 * BackgroundDexopt 的纯 JVM 逻辑测试（不依赖 Android 运行时）：
 * 命令拼装、marker 幂等、假 dex2oat 脚本驱动的编译/失败/跳过路径。
 */
public class BackgroundDexoptTest {

    private static File newZip(File dir, String name, byte[] content) throws Exception {
        File f = new File(dir, name);
        Files.write(f.toPath(), content);
        return f;
    }

    private static byte[] bytes(int len, int seed) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) b[i] = (byte) (i * 31 + seed);
        return b;
    }

    /** 在临时目录生成一个「假 dex2oat」：退出码可控，创建 --oat-file 指向的文件，参数留痕。 */
    private static File fakeDex2oat(File dir, int exitCode, File argvLog) throws Exception {
        File bin = new File(dir, "fake_dex2oat.sh");
        StringBuilder sb = new StringBuilder();
        sb.append("#!/bin/sh\n");
        sb.append("for a in \"$@\"; do\n");
        sb.append("  case \"$a\" in --oat-file=*) touch \"${a#--oat-file=}\" ;; esac\n");
        sb.append("done\n");
        sb.append("echo \"$@\" >> \"").append(argvLog.getAbsolutePath()).append("\"\n");
        if (exitCode != 0) sb.append("exit ").append(exitCode).append("\n");
        Files.write(bin.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
        if (!bin.setExecutable(true)) {
            throw new IllegalStateException("cannot chmod +x fake dex2oat");
        }
        return bin;
    }

    private static String argvOf(File argvLog) throws Exception {
        List<String> lines = Files.readAllLines(argvLog.toPath(), StandardCharsets.UTF_8);
        Assert.assertFalse("假 dex2oat 至少被调用一次", lines.isEmpty());
        return lines.get(lines.size() - 1);
    }

    // ---------- 命令拼装 ----------

    @Test
    public void buildCommandContainsRequiredArguments() {
        List<String> cmd = BackgroundDexopt.buildCommand(
                "/apex/com.android.art/bin/dex2oat64",
                "/data/user/0/x/code_cache/xixin_dexes.zip",
                "/data/user/0/x/code_cache/oat/arm64/xixin_dexes.odex",
                "arm64");
        Assert.assertEquals(5, cmd.size());
        Assert.assertEquals("/apex/com.android.art/bin/dex2oat64", cmd.get(0));
        Assert.assertEquals("--dex-file=/data/user/0/x/code_cache/xixin_dexes.zip", cmd.get(1));
        Assert.assertEquals("--oat-file=/data/user/0/x/code_cache/oat/arm64/xixin_dexes.odex", cmd.get(2));
        Assert.assertEquals("--compiler-filter=quicken", cmd.get(3));
        Assert.assertEquals("--instruction-set=arm64", cmd.get(4));
    }

    // ---------- sha1 / marker ----------

    @Test
    public void sha1HexMatchesKnownVector() throws Exception {
        File f = File.createTempFile("dpt-sha1", ".tmp");
        f.deleteOnExit();
        Files.write(f.toPath(), "abc".getBytes(StandardCharsets.UTF_8));
        // SHA-1("abc") 的 RFC 3174 标准向量
        Assert.assertEquals("a9993e364706816aba3e25717850c26c9cd0d89d", BackgroundDexopt.sha1Hex(f));
    }

    @Test
    public void markerRoundTrip_skipWhenUpToDate() throws Exception {
        File dir = Files.createTempDirectory("dpt-dexopt").toFile();
        File zip = newZip(dir, BackgroundDexopt.DEXES_ZIP_NAME, bytes(1024, 1));
        File argvLog = new File(dir, "argv.log");
        File bin = fakeDex2oat(dir, 0, argvLog);

        BackgroundDexopt.run(dir.getAbsolutePath(), "arm64", bin.getAbsolutePath());

        // 第一次：执行编译 → odex 被假编译器创建 → marker 记录 zip 指纹
        File odex = new File(new File(dir, "oat/arm64"), "xixin_dexes.odex");
        Assert.assertTrue("假编译器应创建 odex", odex.isFile());
        File marker = new File(dir, BackgroundDexopt.DEXES_ZIP_NAME + ".sha1");
        Assert.assertTrue("marker 应写入", marker.isFile());
        String expectedSha1 = BackgroundDexopt.sha1Hex(zip);
        Assert.assertEquals(expectedSha1, new String(Files.readAllBytes(marker.toPath()),
                StandardCharsets.UTF_8).trim());
        Assert.assertTrue("argv 应包含 dex-file 与 oat-file",
                argvOf(argvLog).contains("--dex-file=" + zip.getAbsolutePath())
                        && argvOf(argvLog).contains("--oat-file=" + odex.getAbsolutePath()));

        // 第二次：up-to-date → 假编译器不再被调用（argv 行数不变）
        int callsBefore = Files.readAllLines(argvLog.toPath(), StandardCharsets.UTF_8).size();
        BackgroundDexopt.run(dir.getAbsolutePath(), "arm64", bin.getAbsolutePath());
        Assert.assertEquals("up-to-date 时不得重复编译", callsBefore,
                Files.readAllLines(argvLog.toPath(), StandardCharsets.UTF_8).size());
    }

    @Test
    public void changedZipTriggersRecompilation() throws Exception {
        File dir = Files.createTempDirectory("dpt-dexopt2").toFile();
        File zip = newZip(dir, BackgroundDexopt.DEXES_ZIP_NAME, bytes(512, 3));
        File argvLog = new File(dir, "argv.log");
        File bin = fakeDex2oat(dir, 0, argvLog);

        BackgroundDexopt.run(dir.getAbsolutePath(), "arm64", bin.getAbsolutePath());
        Files.write(zip.toPath(), bytes(512, 9));   // 内容变化（模拟 App 升级）

        BackgroundDexopt.run(dir.getAbsolutePath(), "arm64", bin.getAbsolutePath());
        Assert.assertEquals("zip 变化后必须重编", 2,
                Files.readAllLines(argvLog.toPath(), StandardCharsets.UTF_8).size());
    }

    // ---------- 失败路径 ----------

    @Test
    public void dex2oatFailureDoesNotWriteMarker() throws Exception {
        File dir = Files.createTempDirectory("dpt-dexopt3").toFile();
        newZip(dir, BackgroundDexopt.DEXES_ZIP_NAME, bytes(256, 5));
        File argvLog = new File(dir, "argv.log");
        File bin = fakeDex2oat(dir, 1, argvLog);   // 退出码 1 = 失败

        BackgroundDexopt.run(dir.getAbsolutePath(), "arm64", bin.getAbsolutePath());

        Assert.assertFalse("失败不得写 marker", new File(dir,
                BackgroundDexopt.DEXES_ZIP_NAME + ".sha1").isFile());
    }

    @Test
    public void missingZipIsNoop() throws Exception {
        File dir = Files.createTempDirectory("dpt-dexopt4").toFile();
        File argvLog = new File(dir, "argv.log");
        File bin = fakeDex2oat(dir, 0, argvLog);

        BackgroundDexopt.run(dir.getAbsolutePath(), "arm64", bin.getAbsolutePath());

        Assert.assertFalse("zip 缺失时不得调用 dex2oat", argvLog.isFile());
    }

    // ---------- dex2oat 探测 ----------

    @Test
    public void pickDex2oatReturnsExecutableOrNull() {
        String picked = BackgroundDexopt.pickDex2oat();
        // 环境相关：有 ART apex 的设备返回真实 dex2oat 路径，没有则 null。
        // 契约 = 返回值要么为 null，要么是「存在且可执行」的文件。
        if (picked != null) {
            File f = new File(picked);
            Assert.assertTrue("探测结果必须是存在的可执行文件: " + picked,
                    f.isFile() && f.canExecute());
        }
    }
}
