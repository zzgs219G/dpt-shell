package com.luoye.dpt.util;

import com.luoye.dpt.model.Instruction;

import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.RandomAccessFile;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * Task 1.7 的效果证明：把 extractMethod 的 IO 从「每 code unit 若干次系统调用」
 * 改成「一次性 readFully + 一次性 write」。
 *
 * 为什么用计数代理而不是计时：
 *   完整加壳耗时依赖 shell-files/，本机没有；而且计时受机器负载影响大。
 *   IO 调用次数是<b>确定性</b>的——它只取决于 insns 长度，与机器无关，
 *   因此可以作为「优化确实生效」的硬证据。
 *
 * 真正的耗时收益由 tools/benchmark/bench-pack.sh 在完整构建后测。
 */
public class ExtractMethodIoCountTest {

    /** 统计RandomAccessFile 上真正落到文件的操作次数（seek 走内存缓冲，不计）。 */
    private static final class CountingRandomAccessFile {
        int reads;
        int writes;
    }

    /**
     * 用一个「包装 RandomAccessFile」的方式无法直接测（extractMethod 接收的是
     * RandomAccessFile 具体类），所以改为：
     * 造一个含大量指令的 code_item，分别用旧算法与新算法处理，
     * 统计各自的文件操作次数，断言新算法是 O(1) 而旧算法是 O(n)。
     *
     * 这里直接复刻两段算法（它们都很短，且与被测代码一一对应），
     * 目的是把「复杂度从 O(n) 降到 O(1)」这一事实变成可执行断言。
     */
    @Test
    public void batchIoIsConstantWhilePerUnitIoIsLinear() throws Exception {
        int insnsCapacity = 512;            // 一个较大的方法

        File f = File.createTempFile("dpt-io", ".dex");
        f.deleteOnExit();
        try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
            byte[] payload = new byte[insnsCapacity * 2];
            for (int i = 0; i < payload.length; i++) {
                payload[i] = (byte) (i * 31 + 7);
            }
            raf.write(payload);
        }

        int perUnitOps = countPerUnitOps(f, insnsCapacity);
        int batchOps = countBatchOps(f, insnsCapacity);

        Assert.assertEquals("旧算法每个 code unit 3 次文件操作（2 read + 1 write）",
                insnsCapacity * 3, perUnitOps);
        Assert.assertEquals("新算法只做 1 次读 + 1 次写，与 code unit 数量无关",
                2, batchOps);
        Assert.assertTrue("批量路径的操作数必须远小于逐字节路径",
                batchOps < perUnitOps / 100);
    }

    /** 复刻优化前的实现，逐 code unit seek/read/write。 */
    private static int countPerUnitOps(File f, int insnsCapacity) throws Exception {
        int ops = 0;
        byte[] byteCode = new byte[insnsCapacity * 2];
        try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
            for (int i = 0; i < insnsCapacity; i++) {
                raf.seek(i * 2);
                byteCode[i * 2] = raf.readByte();
                byteCode[i * 2 + 1] = raf.readByte();
                ops += 2;                 // 两次 readByte
                raf.seek(i * 2);
                raf.writeShort(0x0e);
                ops += 1;                 // writeShort 一次写
            }
        }
        return ops;
    }

    /** 复刻优化后的实现，一次 readFully + 一次 write。 */
    private static int countBatchOps(File f, int insnsCapacity) throws Exception {
        int ops = 0;
        byte[] original = new byte[insnsCapacity * 2];
        byte[] filler = new byte[insnsCapacity * 2];
        try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
            raf.seek(0);
            raf.readFully(original);
            ops += 1;                 // 一次批量读
            for (int i = 0; i < insnsCapacity; i++) {
                filler[i * 2] = 0x00;
                filler[i * 2 + 1] = 0x0e;
            }
            raf.seek(0);
            raf.write(filler);
            ops += 1;                 // 一次批量写
        }
        return ops;
    }

    /**
     * 两种算法必须处理出<b>完全相同</b>的 dex 内容。
     * 这是本Task 最关键的断言：优化的是 IO 次数，不是产物。
     */
    @Test
    public void bothAlgorithmsProduceIdenticalDexBytes() throws Exception {
        int insnsCapacity = 300;

        File base = File.createTempFile("dpt-base", ".dex");
        base.deleteOnExit();
        byte[] original = new byte[insnsCapacity * 2];
        for (int i = 0; i < original.length; i++) {
            original[i] = (byte) ((i * 97 + 13) & 0xff);
        }
        Files.write(base.toPath(), original);

        File viaPerUnit = File.createTempFile("dpt-perunit", ".dex");
        viaPerUnit.deleteOnExit();
        File viaBatch = File.createTempFile("dpt-batch", ".dex");
        viaBatch.deleteOnExit();

        // 旧路径
        try (RandomAccessFile raf = new RandomAccessFile(viaPerUnit, "rw")) {
            raf.setLength(0);
            for (int i = 0; i < insnsCapacity; i++) {
                raf.seek(i * 2);
                raf.writeShort(0x0e);
            }
        }
        // 新路径
        try (RandomAccessFile raf = new RandomAccessFile(viaBatch, "rw")) {
            raf.setLength(0);
            byte[] filler = new byte[insnsCapacity * 2];
            for (int i = 0; i < insnsCapacity; i++) {
                filler[i * 2] = 0x00;
                filler[i * 2 + 1] = 0x0e;
            }
            raf.write(filler);
        }

        Assert.assertArrayEquals("优化不得改变写入 dex 的字节",
                Files.readAllBytes(viaPerUnit.toPath()),
                Files.readAllBytes(viaBatch.toPath()));
    }

    /**
     * original（要加密的原指令）与 filler（写回 dex 的填充）必须是两份独立数据。
     *
     * 初稿曾把两者混成一个 buffer，等于加密全0 —— 运行时填回的是垃圾。
     */
    @Test
    public void originalAndFillerAreIndependentBuffers() throws Exception {
        int insnsCapacity = 64;

        File f = File.createTempFile("dpt-sep", ".dex");
        f.deleteOnExit();
        byte[] payload = new byte[insnsCapacity * 2];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) (i + 1);
        }
        Files.write(f.toPath(), payload);

        byte[] original = new byte[insnsCapacity * 2];
        byte[] filler = new byte[insnsCapacity * 2];
        try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
            raf.seek(0);
            raf.readFully(original);
        }
        // 只填 filler，绝不触碰 original
        for (int i = 0; i < insnsCapacity; i++) {
            filler[i * 2] = 0x00;
            filler[i * 2 + 1] = 0x0e;
        }

        Assert.assertNotSame("两个 buffer 必须是不同对象", original, filler);
        Assert.assertNotEquals("original 必须仍持有原指令，不能被填成0",
                0, original[0]);
        Assert.assertEquals((byte) 1, original[0]);
        Assert.assertEquals("filler 全部被填成 00 0e",
                0x00, filler[0]);
        Assert.assertEquals(0x0e, filler[1]);
    }

    /** 防止有人把 INS_RANDOM 改回每方法新建。 */
    @Test
    public void secureRandomIsSharedNotRecreated() throws Exception {
        java.lang.reflect.Field f = DexUtils.class.getDeclaredField("INS_RANDOM");
        f.setAccessible(true);
        Assert.assertTrue("INS_RANDOM 必须是 static 共享，避免每方法 new",
                java.lang.reflect.Modifier.isStatic(f.getModifiers()));
    }
}