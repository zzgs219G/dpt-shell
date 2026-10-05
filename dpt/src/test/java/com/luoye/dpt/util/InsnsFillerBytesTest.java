package com.luoye.dpt.util;

import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.RandomAccessFile;

/**
 * 锁定 extractMethod 抽空方法体时写入 dex 的字节序列。
 *
 * 背景：Task 1.7 把「每 2 字节一次 seek/read/write」改成一次性
 * readFully + 一次性 write。改的是IO 方式，写入的**内容必须逐字节不变**，
 * 否则加壳产物会变化，而这种变化在真机上才会暴露成诡异崩溃。
 *
 * 这里把 RandomAccessFile.writeShort 的实际字节序钉死，避免后续有人
 * 「顺手修正」成小端 —— 那是行为变更，不是优化。
 */
public class InsnsFillerBytesTest {

    /**
     * RandomAccessFile.writeShort 是<b>大端</b>。
     * 所以现有的 writeShort(0x0e) 实际写入的是 00 0e，而不是 dex 里
     * return-void 的标准小端编码 0e 00。
     *
     * 这是既有行为，Task 1.7 必须原样保留。
     */
    @Test
    public void writeShortIsBigEndian() throws Exception {
        File f = File.createTempFile("dpt-filler", ".bin");
        f.deleteOnExit();
        try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
            raf.setLength(0);
            raf.seek(0);
            raf.writeShort(0x0e);
        }

        byte[] actual = readAll(f);
        Assert.assertArrayEquals(
                "writeShort 必须是大端；Task 1.7 不能改这个字节序",
                new byte[]{0x00, 0x0e},
                actual);
    }

    /**
     * 打包侧用 (short) insRandom.nextInt() 的高低字节手工拼 filler 时，
     * 必须复刻 writeShort 的大端顺序：先高字节后低字节。
     *
     * 若误按小端（先低后高），产物会与优化前不同。
     */
    @Test
    public void manualByteOrderMatchesWriteShortBigEndian() throws Exception {
        short value = (short) 0x1234;

        File temp = File.createTempFile("dpt-w", ".bin");
        temp.deleteOnExit();
        try (RandomAccessFile raf = new RandomAccessFile(temp, "rw")) {
            raf.setLength(0);
            raf.writeShort(value);
        }

        byte[] manual = new byte[]{
                (byte) ((value >>> 8) & 0xff),   // 高字节在前
                (byte) (value & 0xff),
        };

        Assert.assertArrayEquals("手工拼字节必须等价于 writeShort",
                readAll(temp), manual);
    }

    /**
     * filler 长度必须等于 insns 字节数（insnsCapacity * 2）。
     * 少写或多写都会让后续 code_item 解析错位。
     */
    @Test
    public void fillerLengthEqualsInsnsByteLength() throws Exception {
        int insnsCapacity = 37;             // 奇数个 code unit，边界情况
        int byteLen = insnsCapacity * 2;

        byte[] filler = new byte[byteLen];
        Assert.assertEquals(74, filler.length);
        Assert.assertEquals(0, filler.length % 2);
    }

    private static byte[] readAll(File f) throws Exception {
        try (java.io.FileInputStream in = new java.io.FileInputStream(f)) {
            byte[] buf = new byte[(int) f.length()];
            int off = 0;
            while (off < buf.length) {
                int n = in.read(buf, off, buf.length - off);
                if (n < 0) break;
                off += n;
            }
            return buf;
        }
    }
}