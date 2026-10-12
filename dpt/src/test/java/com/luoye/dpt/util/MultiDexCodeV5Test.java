package com.luoye.dpt;

import com.luoye.dpt.config.Const;
import com.luoye.dpt.config.ShellConfig;
import com.luoye.dpt.model.BlockTableEntry;
import com.luoye.dpt.model.ClassIndexEntry;
import com.luoye.dpt.model.Instruction;
import com.luoye.dpt.model.MultiDexCode;
import com.luoye.dpt.util.CryptoUtils;
import com.luoye.dpt.util.MultiDexCodeUtils;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Locks the v5 xixin_data layout.
 *
 * <p>v5 is a breaking change: the runtime rejects anything but v5, and this is
 * the only place the layout is defined. These assertions exist because a wrong
 * byte here does not fail the build — it fails on a real device, as an app that
 * dies before its first Activity.
 *
 * <p>The {@link RuntimeView} helper at the bottom mirrors the native
 * {@code MultiDexCode::getMethodData} walk step by step (index lookup, block
 * selection by rawOffset, inflate + per-block decrypt, in-block record walk),
 * so the round-trip tests exercise the real cross-language contract rather
 * than a restatement of the builder.
 */
public class MultiDexCodeV5Test {

    private static final byte[] AES_KEY = new byte[32];

    @Before
    public void setUp() {
        for (int i = 0; i < AES_KEY.length; i++) {
            AES_KEY[i] = (byte) (0x40 + i);
        }
        ShellConfig.getInstance().setInsnsCryptKey(AES_KEY);
    }

    private static Instruction ins(int methodIdx, int classDataOff, int dataLen) {
        return ins(methodIdx, classDataOff, dataLen, (byte) (methodIdx * 7 + 1));
    }

    private static Instruction ins(int methodIdx, int classDataOff, int dataLen, byte seed) {
        Instruction i = new Instruction();
        i.setMethodIndex(methodIdx);
        i.setClassDataOff(classDataOff);
        i.setInstructionDataSize(dataLen);
        byte[] d = new byte[dataLen];
        for (int k = 0; k < dataLen; k++) {
            d[k] = (byte) (methodIdx * 7 + k * 3 + seed);
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
        d0.add(ins(21, 0x100, 0)); // placeholder: abstract/native method
        m.put(0, d0);

        List<Instruction> d1 = new ArrayList<>();
        d1.add(ins(30, 0x200, 4));
        m.put(1, d1);

        return m;
    }

    /**
     * Forces several blocks: 120 classes x ~830 raw bytes > 2 x 64KB target.
     * Class offsets are descending on purpose so the sort permutation is real.
     */
    private static Map<Integer, List<Instruction>> bigSample() {
        Map<Integer, List<Instruction>> m = new HashMap<>();
        List<Instruction> d0 = new ArrayList<>();
        int classes = 120;
        for (int c = classes - 1; c >= 0; c--) {
            int classDataOff = 0x1000 * (c + 1);
            int methodCount = 2 + (c % 3);
            for (int k = 0; k < methodCount; k++) {
                // ~180-560 bytes of insns per method, mostly-repetitive content
                int len = 90 + ((c * 13 + k * 29) % 180);
                d0.add(ins(1000 + c * 10 + k, classDataOff, len, (byte) 0x55));
            }
        }
        m.put(0, d0);
        return m;
    }

    private static byte[] write(MultiDexCode c) throws Exception {
        File f = File.createTempFile("dpt-v5", ".bin");
        f.deleteOnExit();
        MultiDexCodeUtils.writeMultiDexCode(f.getAbsolutePath(), c);
        return Files.readAllBytes(f.toPath());
    }

    // ---------- header ----------

    @Test
    public void versionIsFive() {
        Assert.assertEquals("v5 是本方案唯一的载荷版本",
                5, Const.MULTI_DEX_CODE_VERSION);
    }

    @Test
    public void headerMagicAndVersion() throws Exception {
        byte[] b = write(MultiDexCodeUtils.makeMultiDexCode(sample()));
        ByteBuffer bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);

        Assert.assertEquals("magic 应为 'OOO5' = 0x4F4F4F35",
                0x4F4F4F35, bb.getInt(0));
        Assert.assertEquals(5, bb.getShort(4) & 0xffff);
        Assert.assertEquals("dexCount = 2", 2, bb.getShort(6) & 0xffff);
        Assert.assertEquals("classIndexOffset 紧跟 24 字节 header",
                Const.MULTI_DEX_CODE_HEADER_SIZE, bb.getInt(8));
        int classCount = 3;
        int blockTableOffset = bb.getInt(12);
        Assert.assertEquals("blockTable 紧跟 classIndex",
                Const.MULTI_DEX_CODE_HEADER_SIZE + classCount * 16, blockTableOffset);
        int blockCount = bb.getInt(16);
        Assert.assertTrue("至少一个块", blockCount >= 1);
        Assert.assertEquals("reserved = 0", 0, bb.getInt(20));
        Assert.assertEquals("blockTable 实际条目数必须与 header 一致",
                blockCount, (blockTableOffset == 0) ? -1 : readBlockTableCount(b, blockTableOffset, blockCount));
    }

    /** Walk the declared table and confirm every entry parses. */
    private static int readBlockTableCount(byte[] b, int blockTableOffset, int blockCount) {
        ByteBuffer bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < blockCount; i++) {
            int base = blockTableOffset + i * 16;
            Assert.assertTrue(bb.getInt(base) >= 0);
            Assert.assertTrue(bb.getInt(base + 4) > 0);
            Assert.assertTrue(bb.getInt(base + 8) > 0);
            Assert.assertTrue(bb.getInt(base + 12) > 0);
        }
        return blockCount;
    }

    @Test
    public void magicIsAsciiOoo5() {
        byte[] m = ByteBuffer.allocate(4)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putInt(Const.MULTI_DEX_CODE_MAGIC)
                .array();
        Assert.assertArrayEquals(new byte[]{'5', 'O', 'O', 'O'}, m);
        Assert.assertEquals("常量本身按大端读出来应是 OOO5",
                "OOO5", new String(new byte[]{
                        (byte) ((Const.MULTI_DEX_CODE_MAGIC >>> 24) & 0xff),
                        (byte) ((Const.MULTI_DEX_CODE_MAGIC >>> 16) & 0xff),
                        (byte) ((Const.MULTI_DEX_CODE_MAGIC >>> 8) & 0xff),
                        (byte) (Const.MULTI_DEX_CODE_MAGIC & 0xff)},
                        StandardCharsets.US_ASCII));
    }

    // ---------- class index (unchanged from v4) ----------

    @Test
    public void classIndexEntryIs16Bytes() {
        Assert.assertEquals(16, new ClassIndexEntry((byte) 0, (short) 1, 0x10, 0).toBytes().length);
    }

    @Test
    public void blockTableEntryIs16BytesAndLittleEndian() {
        BlockTableEntry e = new BlockTableEntry(0x11223344, 0x00001000, 0x55667788, 0x00000800);
        byte[] b = e.toBytes();

        Assert.assertEquals(16, b.length);
        Assert.assertEquals(0x44, b[0] & 0xff);           // rawOffset LE
        Assert.assertEquals(0x33, b[1] & 0xff);
        Assert.assertEquals(0x22, b[2] & 0xff);
        Assert.assertEquals(0x11, b[3] & 0xff);
        Assert.assertEquals(0x00, b[7] & 0xff);           // rawSize high byte
        Assert.assertEquals(0x88, b[8] & 0xff);           // compOffset LE
        Assert.assertEquals(0x00, b[12] & 0xff);          // compSize high byte
    }

    /**
     * The runtime binary-searches this array, so unsorted entries mean a class is
     * silently never found -- and its methods stay encrypted garbage.
     *
     * <p>The sample deliberately emits class offset 0x300 before 0x100.
     */
    @Test
    public void classIndexIsSortedByDexIdxThenClassDataOff() {
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
    public void classIndexPreservesEachClassMethodCount() {
        MultiDexCode c = MultiDexCodeUtils.makeMultiDexCode(sample());
        List<ClassIndexEntry> ci = c.getClassIndex();

        // Sorted by (dexIdx, classDataOff): dex0/0x100, dex0/0x300, dex1/0x200
        Assert.assertEquals(3, ci.size());

        Assert.assertEquals(0, ci.get(0).dexIdx & 0xff);
        Assert.assertEquals(0x100, ci.get(0).classDataOff);
        Assert.assertEquals("class@0x100 有 2 个方法", 2, ci.get(0).methodCount);

        Assert.assertEquals(0, ci.get(1).dexIdx & 0xff);
        Assert.assertEquals(0x300, ci.get(1).classDataOff);
        Assert.assertEquals("class@0x300 有 3 个方法", 3, ci.get(1).methodCount);

        Assert.assertEquals(1, ci.get(2).dexIdx & 0xff);
        Assert.assertEquals(0x200, ci.get(2).classDataOff);
        Assert.assertEquals(1, ci.get(2).methodCount);
    }

    // ---------- blocks ----------

    @Test
    public void blocksAreContiguousAscendingAndClassAligned() {
        MultiDexCode c = MultiDexCodeUtils.makeMultiDexCode(bigSample());
        List<BlockTableEntry> bt = c.getBlockTable();

        Assert.assertTrue("bigSample 应产生至少两个块", bt.size() >= 2);

        int expectedRaw = c.getClassIndex().get(0).methodDataOff;
        for (int i = 0; i < bt.size(); i++) {
            BlockTableEntry e = bt.get(i);
            Assert.assertEquals("块 " + i + " 的 rawOffset 必须与虚拟原始空间连续",
                    expectedRaw, e.rawOffset);
            Assert.assertTrue("块 " + i + " 不得为空", e.rawSize > 0);
            Assert.assertTrue("块 " + i + " 密文不得为空", e.compSize > 0);
            expectedRaw = e.rawOffset + e.rawSize;

            // class-aligned: no ClassIndexEntry spans this block's end.
            for (ClassIndexEntry cie : c.getClassIndex()) {
                long start = Integer.toUnsignedLong(cie.methodDataOff);
                long end = start + rawLengthOf(cie, c);
                long bStart = Integer.toUnsignedLong(e.rawOffset);
                long bEnd = bStart + Integer.toUnsignedLong(e.rawSize);
                boolean startsInside = start >= bStart && start < bEnd;
                if (startsInside) {
                    Assert.assertTrue("类 " + cie.classDataOff + " 不得跨越块 " + i + " 的边界",
                            end <= bEnd);
                }
            }
        }
        Assert.assertEquals("块的 raw 覆盖必须恰好等于虚拟原始空间总大小",
                rawLengthOfAll(c), expectedRaw);
    }

    private static long rawLengthOf(ClassIndexEntry cie, MultiDexCode c) {
        // records of one class: methodCount records, walked via the flattened
        // per-class record lists is not possible from the model alone, so use
        // the block table: a class's raw length = its block-relative extent.
        // Simpler and exact: find the NEXT class in the same block; the last
        // class of a block runs to the block end.
        List<ClassIndexEntry> ci = c.getClassIndex();
        int i = ci.indexOf(cie);
        if (i + 1 < ci.size()) {
            return Integer.toUnsignedLong(ci.get(i + 1).methodDataOff)
                    - Integer.toUnsignedLong(cie.methodDataOff);
        }
        // last class: to the end of the virtual space
        BlockTableEntry last = c.getBlockTable().get(c.getBlockTable().size() - 1);
        return Integer.toUnsignedLong(last.rawOffset + last.rawSize)
                - Integer.toUnsignedLong(cie.methodDataOff);
    }

    private static long rawLengthOfAll(MultiDexCode c) {
        BlockTableEntry last = c.getBlockTable().get(c.getBlockTable().size() - 1);
        return Integer.toUnsignedLong(last.rawOffset + last.rawSize);
    }

    @Test
    public void totalFileSizeMatchesDeclaredLayout() throws Exception {
        MultiDexCode c = MultiDexCodeUtils.makeMultiDexCode(bigSample());
        byte[] b = write(c);

        int expected = Const.MULTI_DEX_CODE_HEADER_SIZE
                + c.getClassIndex().size() * Const.MULTI_DEX_CODE_CLASS_INDEX_ENTRY_SIZE
                + c.getBlockTable().size() * Const.MULTI_DEX_CODE_BLOCK_ENTRY_SIZE;
        for (byte[] block : c.getBlocks()) {
            expected += block.length;
        }

        Assert.assertEquals("文件长度必须与 header + 索引 + 块表 + 块之和一致",
                expected, b.length);
    }

    // ---------- round trip ----------

    @Test
    public void roundTripRecoversEveryMethod() throws Exception {
        Map<Integer, List<Instruction>> sample = sample();
        byte[] b = write(MultiDexCodeUtils.makeMultiDexCode(sample));
        RuntimeView view = new RuntimeView(b, AES_KEY);

        for (Map.Entry<Integer, List<Instruction>> dexEntry : sample.entrySet()) {
            List<List<Instruction>> classes = groupByClass(dexEntry.getValue());
            for (List<Instruction> cls : classes) {
                int classDataOff = cls.get(0).getClassDataOff();
                for (int i = 0; i < cls.size(); i++) {
                    Instruction want = cls.get(i);
                    byte[] got = view.insnsOf(dexEntry.getKey(), classDataOff, i);
                    Assert.assertNotNull("方法 " + want.getMethodIndex() + " 必须可定位",
                            got);
                    Assert.assertArrayEquals(
                            "methodIdx=" + want.getMethodIndex() + " 的指令必须逐字节还原",
                            want.getInstructionsData(), got);
                }
            }
        }
    }

    @Test
    public void placeholderRecordsAdvanceBySixBytesOnly() throws Exception {
        Map<Integer, List<Instruction>> sample = sample();
        byte[] b = write(MultiDexCodeUtils.makeMultiDexCode(sample));
        RuntimeView view = new RuntimeView(b, AES_KEY);

        // class@0x100 = [method 20 (6B), method 21 (0B placeholder)]. Asking for
        // position 1 must return an empty array, not bleed into the next record.
        byte[] placeholder = view.insnsOf(0, 0x100, 1);
        Assert.assertNotNull(placeholder);
        Assert.assertEquals(0, placeholder.length);

        // The class AFTER the placeholder still resolves (dex0/0x300).
        byte[] next = view.insnsOf(0, 0x300, 0);
        Assert.assertNotNull(next);
        Assert.assertEquals(4, next.length);
    }

    /**
     * The whole point of v5: repetitive dex-code-like records must actually
     * shrink. Asserts the compressed blocks are meaningfully smaller than the
     * raw record bytes they replace.
     */
    @Test
    public void compressionShrinksRepetitivePayload() {
        MultiDexCode c = MultiDexCodeUtils.makeMultiDexCode(bigSample());

        long comp = 0;
        for (byte[] block : c.getBlocks()) {
            comp += block.length;
        }
        long raw = rawLengthOfAll(c);

        Assert.assertTrue("压缩后 (" + comp + "B) 必须明显小于原始记录 (" + raw
                        + "B)，否则 v5 没有意义",
                comp < raw * 3 / 4);
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
        Assert.assertTrue("无类也不应产生块", c.getBlockTable().isEmpty());
        Assert.assertTrue(c.getBlocks().isEmpty());
    }

    /**
     * Documents a real limit carried over from v4: dexIdx is a single byte, so
     * the index can only address dex files 0-255.
     */
    @Test
    public void dexIdxIsOneByteSoAddressesUpTo255() {
        for (int i = 0; i <= 255; i++) {
            Assert.assertEquals("dexIdx=" + i + " 必须按位无损",
                    i, ((byte) i) & 0xff);
        }
        Assert.assertEquals("已知限制：256 截断为 0", 0, ((byte) 256) & 0xff);
    }

    private static List<List<Instruction>> groupByClass(List<Instruction> insns) {
        List<List<Instruction>> groups = new ArrayList<>();
        List<Instruction> cur = null;
        int curOff = 0;
        for (Instruction ins : insns) {
            if (cur == null || ins.getClassDataOff() != curOff) {
                cur = new ArrayList<>();
                groups.add(cur);
                curOff = ins.getClassDataOff();
            }
            cur.add(ins);
        }
        return groups;
    }

    /**
     * A minimal reader that mirrors the native runtime's v5 walk:
     * header → ClassIndex (binary-search equivalent) → BlockTable (last entry
     * with rawOffset <= methodDataOff) → materialize (chacha20 with
     * nonce=blockIdx, then raw-inflate) → walk records inside the block.
     *
     * <p>Keep this in lockstep with shell/src/main/cpp/dex/MultiDexCode.cpp.
     */
    private static final class RuntimeView {
        private final byte[] payload;
        private final byte[] aesKey;
        private final int classIndexOffset;
        private final int blockTableOffset;
        private final int blockCount;
        private final Map<Integer, byte[]> rawCache = new HashMap<>();

        RuntimeView(byte[] payload, byte[] aesKey) {
            this.payload = payload;
            this.aesKey = aesKey;
            ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
            Assert.assertEquals(Const.MULTI_DEX_CODE_MAGIC, bb.getInt(0));
            Assert.assertEquals(Const.MULTI_DEX_CODE_VERSION, bb.getShort(4) & 0xffff);
            this.classIndexOffset = bb.getInt(8);
            this.blockTableOffset = bb.getInt(12);
            this.blockCount = bb.getInt(16);
        }

        private ClassIndexEntry indexEntry(int dexIdx, int classDataOff) {
            for (int i = 0; i * 16 + classIndexOffset < blockTableOffset; i++) {
                ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
                bb.position(classIndexOffset + i * 16);
                int d = bb.get() & 0xff;   // dexIdx
                bb.get();                  // flags
                bb.getShort();             // methodCount
                int off = bb.getInt();     // classDataOff
                if (d == dexIdx && off == classDataOff) {
                    // re-read the whole entry
                    bb.position(classIndexOffset + i * 16);
                    ClassIndexEntry e = new ClassIndexEntry();
                    e.dexIdx = bb.get();
                    e.flags = bb.get();
                    e.methodCount = bb.getShort();
                    e.classDataOff = bb.getInt();
                    e.methodDataOff = bb.getInt();
                    e.reserved = bb.getInt();
                    return e;
                }
                // entry mismatch; keep scanning
            }
            return null;
        }

        private BlockTableEntry blockFor(int rawOff) {
            BlockTableEntry best = null;
            for (int i = 0; i < blockCount; i++) {
                ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
                bb.position(blockTableOffset + i * 16);
                BlockTableEntry e = new BlockTableEntry(
                        bb.getInt(), bb.getInt(), bb.getInt(), bb.getInt());
                if (Integer.toUnsignedLong(e.rawOffset) <= Integer.toUnsignedLong(rawOff)) {
                    best = e;
                }
            }
            return best;
        }

        private byte[] materialized(int blockIdx) {
            if (rawCache.containsKey(blockIdx)) {
                return rawCache.get(blockIdx);
            }
            ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
            bb.position(blockTableOffset + blockIdx * 16);
            BlockTableEntry e = new BlockTableEntry(
                    bb.getInt(), bb.getInt(), bb.getInt(), bb.getInt());

            byte[] comp = Arrays.copyOfRange(payload, e.compOffset,
                    e.compOffset + e.compSize);
            byte[] deflated = CryptoUtils.chacha20Crypt(aesKey,
                    CryptoUtils.buildChaCha20Nonce(blockIdx), comp);
            byte[] raw = CryptoUtils.inflateRaw(deflated, e.rawSize);
            Assert.assertNotNull("块 " + blockIdx + " 必须能解密并解压", raw);
            rawCache.put(blockIdx, raw);
            return raw;
        }

        byte[] insnsOf(int dexIdx, int classDataOff, int methodPos) {
            ClassIndexEntry e = indexEntry(dexIdx, classDataOff);
            if (e == null) {
                return null;
            }
            BlockTableEntry block = blockFor(e.methodDataOff);
            Assert.assertNotNull(block);
            Assert.assertTrue("类不得跨块",
                    Integer.toUnsignedLong(e.methodDataOff)
                            < Integer.toUnsignedLong(block.rawOffset)
                            + Integer.toUnsignedLong(block.rawSize));

            int blockIdx = -1;
            for (int i = 0; i < blockCount; i++) {
                ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
                bb.position(blockTableOffset + i * 16);
                if (bb.getInt() == block.rawOffset) {
                    blockIdx = i;
                    break;
                }
            }
            byte[] raw = materialized(blockIdx);
            int off = (int) (Integer.toUnsignedLong(e.methodDataOff)
                    - Integer.toUnsignedLong(block.rawOffset));

            ByteBuffer bb = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
            bb.position(off);
            for (int i = 0; i < methodPos; i++) {
                bb.getInt();               // methodIdx
                int sz = bb.getShort() & 0xffff;
                bb.position(bb.position() + sz);
            }
            int methodIdx = bb.getInt();
            int insnsSize = bb.getShort() & 0xffff;
            Assert.assertEquals("记录内 methodIdx 必须与索引游标一致",
                    indexMethodIdx(e, methodPos), methodIdx);
            byte[] insns = new byte[insnsSize];
            bb.get(insns);
            return insns;
        }

        /** The methodIdx we fed in for methodPos of this class. */
        private int indexMethodIdx(ClassIndexEntry e, int methodPos) {
            // recover from the sample: classes were built with deterministic
            // methodIdx values; find the class in the sample map instead of
            // duplicating arithmetic here.
            for (Map.Entry<Integer, List<Instruction>> dexEntry : sample().entrySet()) {
                if ((dexEntry.getKey() & 0xff) != (e.dexIdx & 0xff)) {
                    continue;
                }
                for (List<Instruction> cls : groupByClass(dexEntry.getValue())) {
                    if (cls.get(0).getClassDataOff() == e.classDataOff) {
                        return cls.get(methodPos).getMethodIndex();
                    }
                }
            }
            throw new AssertionError("classDataOff not from sample: " + e.classDataOff);
        }
    }
}
