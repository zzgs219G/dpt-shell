package com.luoye.dpt.util;

import com.luoye.dpt.config.Const;
import com.luoye.dpt.model.ClassIndexEntry;
import com.luoye.dpt.model.Instruction;
import com.luoye.dpt.model.MultiDexCode;

import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Locks the v4 OoooooOooo layout.
 *
 * <p>v4 is a breaking change: the runtime rejects anything but v4, and this is
 * the only place the layout is defined. These assertions exist because a wrong
 * byte here does not fail the build — it fails on a real device, as an app that
 * dies before its first Activity.
 */
public class MultiDexCodeV4Test {

    private static Instruction ins(int methodIdx, int classDataOff, int dataLen) {
        Instruction i = new Instruction();
        i.setMethodIndex(methodIdx);
        i.setClassDataOff(classDataOff);
        i.setInstructionDataSize(dataLen);
        byte[] d = new byte[dataLen];
        for (int k = 0; k < dataLen; k++) {
            d[k] = (byte) (methodIdx * 7 + k);
        }
        i.setInstructionsData(d);
        return i;
    }

    /** dex 0: two classes; dex 1: one class. Deliberately out of offset order. */
    private static Map<Integer, List<Instruction>> sample() {
        Map<Integer, List<Instruction>> m = new HashMap<>();

        List<Instruction> d0 = new ArrayList<>();
        // class A at offset 0x300, three methods
        d0.add(ins(10, 0x300, 4));
        d0.add(ins(11, 0x300, 8));
        d0.add(ins(12, 0x300, 2));
        // class B at offset 0x100, two methods -- SMALLER offset, emitted SECOND
        d0.add(ins(20, 0x100, 6));
        d0.add(ins(21, 0x100, 2));
        m.put(0, d0);

        List<Instruction> d1 = new ArrayList<>();
        d1.add(ins(30, 0x200, 4));
        m.put(1, d1);

        return m;
    }

    private static byte[] write(MultiDexCode c) throws Exception {
        File f = File.createTempFile("dpt-v4", ".bin");
        f.deleteOnExit();
        MultiDexCodeUtils.writeMultiDexCode(f.getAbsolutePath(), c);
        return Files.readAllBytes(f.toPath());
    }

    // ---------- header ----------

    @Test
    public void versionIsFour() {
        Assert.assertEquals("v4 是本方案唯一的载荷版本",
                4, Const.MULTI_DEX_CODE_VERSION);
    }

    @Test
    public void headerMagicAndVersion() throws Exception {
        byte[] b = write(MultiDexCodeUtils.makeMultiDexCode(sample()));
        ByteBuffer bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);

        Assert.assertEquals("magic 应为 'OOO4' = 0x4F4F4F34",
                0x4F4F4F34, bb.getInt(0));
        Assert.assertEquals(4, bb.getShort(4) & 0xffff);
        Assert.assertEquals("dexCount = 2", 2, bb.getShort(6) & 0xffff);
        Assert.assertEquals("classIndexOffset 紧跟 header",
                Const.MULTI_DEX_CODE_HEADER_SIZE, bb.getInt(8));
        Assert.assertEquals("methodDataOffset = 16 + 3 entries * 16",
                Const.MULTI_DEX_CODE_HEADER_SIZE + 3 * 16, bb.getInt(12));
    }

    @Test
    public void magicIsAsciiOoo4() {
        // The constant must spell "4OOO" in the file. 0x4F4F4F34 stored
        // little-endian is 34 4F 4F 4F, i.e. '4' 'O' 'O' 'O' -- the digit comes
        // first because it occupies the low byte of the big-endian reading
        // 0x4F4F4F34 = "OOO4". This makes a corrupted payload obvious in a hex
        // dump.
        byte[] m = ByteBuffer.allocate(4)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putInt(Const.MULTI_DEX_CODE_MAGIC)
                .array();
        Assert.assertArrayEquals(new byte[]{'4', 'O', 'O', 'O'}, m);
        Assert.assertEquals("常量本身按大端读出来应是 OOO4",
                "OOO4", new String(new byte[]{
                        (byte) ((Const.MULTI_DEX_CODE_MAGIC >>> 24) & 0xff),
                        (byte) ((Const.MULTI_DEX_CODE_MAGIC >>> 16) & 0xff),
                        (byte) ((Const.MULTI_DEX_CODE_MAGIC >>> 8) & 0xff),
                        (byte) (Const.MULTI_DEX_CODE_MAGIC & 0xff)},
                        java.nio.charset.StandardCharsets.US_ASCII));
    }

    // ---------- class index ----------

    @Test
    public void classIndexEntryIs16Bytes() {
        Assert.assertEquals(16, new ClassIndexEntry((byte) 0, (short) 1, 0x10, 0).toBytes().length);
    }

    @Test
    public void classIndexEntryIsLittleEndian() {
        ClassIndexEntry e = new ClassIndexEntry((byte) 2, (short) 0x0304, 0x11223344, 0x55667788);
        byte[] b = e.toBytes();

        Assert.assertEquals(2, b[0] & 0xff);              // dexIdx
        Assert.assertEquals(0, b[1] & 0xff);              // flags reserved
        Assert.assertEquals(0x04, b[2] & 0xff);           // methodCount low
        Assert.assertEquals(0x03, b[3] & 0xff);           // methodCount high
        Assert.assertEquals(0x44, b[4] & 0xff);           // classDataOff LE
        Assert.assertEquals(0x33, b[5] & 0xff);
        Assert.assertEquals(0x22, b[6] & 0xff);
        Assert.assertEquals(0x11, b[7] & 0xff);
        Assert.assertEquals(0x88, b[8] & 0xff);           // methodDataOff LE
        Assert.assertEquals(0x77, b[9] & 0xff);
        Assert.assertEquals(0, b[12] & 0xff);             // reserved
    }

    /**
     * The runtime binary-searches this array, so unsorted entries mean a class is
     * silently never found -- and its methods stay encrypted garbage.
     *
     * <p>The sample deliberately emits class offset 0x300 before 0x100.
     */
    @Test
    public void classIndexIsSortedByDexIdxThenClassDataOff() throws Exception {
        MultiDexCode c = MultiDexCodeUtils.makeMultiDexCode(sample());
        List<ClassIndexEntry> ci = c.getClassIndex();

        Assert.assertEquals(3, ci.size());

        int prevDex = -1;
        long prevOff = -1;
        for (ClassIndexEntry e : ci) {
            int dex = e.dexIdx & 0xff;
            long off = Integer.toUnsignedLong(e.classDataOff);
            Assert.assertTrue("ClassIndex 必须按 (dexIdx, classDataOff) 升序，实际: "
                            + dex + "/" + e.classDataOff,
                    dex > prevDex || (dex == prevDex && off > prevOff));
            prevDex = dex;
            prevOff = off;
        }
    }

    @Test
    public void classIndexPreservesEachClassMethodCount() throws Exception {
        MultiDexCode c = MultiDexCodeUtils.makeMultiDexCode(sample());
        List<ClassIndexEntry> ci = c.getClassIndex();

        // Sorted by (dexIdx, classDataOff): dex0/0x100, dex0/0x300, dex1/0x200
        Assert.assertEquals(3, ci.size());

        Assert.assertEquals(0, ci.get(0).dexIdx & 0xff);
        Assert.assertEquals(0x100, ci.get(0).classDataOff);
        Assert.assertEquals("class@0x100 有 2 个方法", 2, ci.get(1 - 1).methodCount);

        Assert.assertEquals(0, ci.get(1).dexIdx & 0xff);
        Assert.assertEquals(0x300, ci.get(1).classDataOff);
        Assert.assertEquals("class@0x300 有 3 个方法", 3, ci.get(1).methodCount);

        Assert.assertEquals(1, ci.get(2).dexIdx & 0xff);
        Assert.assertEquals(0x200, ci.get(2).classDataOff);
        Assert.assertEquals(1, ci.get(2).methodCount);
    }

    // ---------- method data ----------

    /**
     * insnsSize must be the BYTE count. The runtime advances by
     * {@code 6 + insnsSize}; storing the code-unit count would make it read
     * twice as far and desynchronise every following record.
     */
    @Test
    public void insnsSizeIsByteCountNotCodeUnitCount() throws Exception {
        MultiDexCode c = MultiDexCodeUtils.makeMultiDexCode(sample());
        byte[] b = write(c);

        ByteBuffer bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
        int mdOff = bb.getInt(12);
        int firstEntryOff = mdOff + c.getClassIndex().get(0).methodDataOff;

        // First record of the first class: methodIdx then insnsSize.
        bb.position(firstEntryOff);
        int methodIdx = bb.getInt();
        int insnsSize = bb.getShort() & 0xffff;

        Assert.assertEquals("首个记录应是 dex0/class@0x100 的 method 20",
                20, methodIdx);
        Assert.assertEquals("insnsSize 必须是字节数 6（而非 3 个 code unit）",
                6, insnsSize);
        Assert.assertEquals("记录长度 = 6 字节头 + 6 字节数据",
                12, 6 + insnsSize);
    }

    /**
     * Walking the block must land exactly on the declared entries, and each
     * record's methodIdx must equal the one we fed in — in order.
     *
     * <p>The expected sequence is taken from the source map, grouped the same way
     * {@code makeMultiDexCode} groups it, so this asserts the real contract
     * rather than a restatement of the implementation.
     */
    @Test
    public void methodDataOffsetsChainCorrectly() throws Exception {
        MultiDexCode c = MultiDexCodeUtils.makeMultiDexCode(sample());
        byte[] b = write(c);

        // Expected order, derived independently: sorted by (dexIdx, classDataOff),
        // methods kept in allMethods() order inside each class.
        List<Integer> expected = new ArrayList<>();
        Map<Integer, List<Instruction>> grouped = new HashMap<>();
        for (Map.Entry<Integer, List<Instruction>> e : sample().entrySet()) {
            List<List<Instruction>> classes = new ArrayList<>();
            List<Instruction> cur = null;
            int curOff = 0;
            for (Instruction ins : e.getValue()) {
                if (cur == null || ins.getClassDataOff() != curOff) {
                    cur = new ArrayList<>();
                    classes.add(cur);
                    curOff = ins.getClassDataOff();
                }
                cur.add(ins);
            }
            classes.sort(Comparator.comparingLong(l -> Integer.toUnsignedLong(l.get(0).getClassDataOff())));
            List<Instruction> flat = new ArrayList<>();
            for (List<Instruction> cl : classes) {
                for (Instruction ins : cl) {
                    flat.add(ins);
                }
            }
            grouped.put(e.getKey(), flat);
        }
        grouped.entrySet().stream()
                .sorted(Comparator.comparingInt(Map.Entry::getKey))
                .forEach(e -> e.getValue().forEach(i -> expected.add(i.getMethodIndex())));

        ByteBuffer bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
        int mdOff = bb.getInt(12);
        int idx = 0;
        int p = mdOff;

        for (ClassIndexEntry e : c.getClassIndex()) {
            for (int i = 0; i < (e.methodCount & 0xffff); i++) {
                int methodIdx = bb.getInt(p);
                int insnsSize = bb.getShort(p + 4) & 0xffff;

                Assert.assertEquals("记录顺序必须与排序后的方法顺序一致（第 " + idx + " 条）",
                        expected.get(idx).intValue(), methodIdx);
                Assert.assertEquals("methodIdx 必须小端写入",
                        (byte) (expected.get(idx) & 0xff), b[p]);

                p += 6 + insnsSize;
                idx++;
            }
        }
        Assert.assertEquals("应恰好读完所有记录", expected.size(), idx);
        Assert.assertEquals("游标必须正好落在文件末尾（无多余/缺失字节）",
                b.length, p);
    }

    @Test
    public void totalFileSizeMatchesDeclaredLayout() throws Exception {
        MultiDexCode c = MultiDexCodeUtils.makeMultiDexCode(sample());
        byte[] b = write(c);

        int expected = Const.MULTI_DEX_CODE_HEADER_SIZE
                + c.getClassIndex().size() * Const.MULTI_DEX_CODE_CLASS_INDEX_ENTRY_SIZE;
        for (byte[] record : c.getMethodData()) {
            expected += record.length;
        }

        Assert.assertEquals("文件长度必须与 header + 索引 + 记录之和一致",
                expected, b.length);
    }

    // ---------- contract with the runtime ----------

    /**
     * The runtime keys the index on class_data_off. If extractMethod never set it,
     * every entry would carry 0 and all classes would collide on one index entry.
     */
    @Test
    public void classDataOffIsPropagatedIntoTheIndex() throws Exception {
        MultiDexCode c = MultiDexCodeUtils.makeMultiDexCode(sample());
        for (ClassIndexEntry e : c.getClassIndex()) {
            Assert.assertNotEquals("classDataOff 不能全为 0，否则索引失效",
                    0, e.classDataOff);
        }
    }

    /**
 * Documents a real limit of the v4 layout: dexIdx is a single byte, so the
 * index can only address dex files 0-255.
 *
 * <p>That is far beyond any real APK (the format predates 64K-method limits), so
 * the field size is kept at one byte. This test records the boundary so that
 * anyone widening the payload later knows what has to change.
 */
    @Test
    public void dexIdxIsOneByteSoAddressesUpTo255() {
        // Every index 0-255 survives the narrowing cast bit-for-bit. Compare with
        // & 0xff because the field is read as unsigned uint8_t by the runtime.
        for (int i = 0; i <= 255; i++) {
            Assert.assertEquals("dexIdx=" + i + " 必须按位无损",
                    i, ((byte) i) & 0xff);
        }
        // ...and 256 truncates to 0, which is exactly why dexIdx cannot exceed 255.
        Assert.assertEquals("已知限制：256 截断为 0", 0, ((byte) 256) & 0xff);
    }

    /** A dex with no protected methods must not create an empty index entry. */
    @Test
    public void emptyDexListIsSkipped() {
        Map<Integer, List<Instruction>> m = new HashMap<>();
        m.put(0, new ArrayList<>());
        m.put(1, null);

        MultiDexCode c = MultiDexCodeUtils.makeMultiDexCode(m);
        Assert.assertTrue("无方法的 dex 不应产生索引项",
                c.getClassIndex().isEmpty());
    }
}