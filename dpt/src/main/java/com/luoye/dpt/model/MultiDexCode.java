package com.luoye.dpt.model;

import java.util.List;

/**
 * xixin_data payload, v5 layout.
 *
 * <pre>
 * Header (24 bytes)
 *   u32 magic = 0x4F4F4F35 ("OOO5")
 *   u16 version = 5
 *   u16 dexCount
 *   u32 classIndexOffset
 *   u32 blockTableOffset
 *   u32 blockCount
 *   u32 reserved          written 0
 *
 * ClassIndex[] (16 bytes per entry, sorted by (dexIdx, classDataOff) unsigned
 * ascending) — identical to v4:
 *   +0  u8  dexIdx
 *   +1  u8  flags        reserved, written 0
 *   +2  u16 methodCount
 *   +4  u32 classDataOff
 *   +8  u32 methodDataOff  relative offset in the *virtual raw* method-data
 *                          space (see below)
 *   +12 u32 reserved       written 0
 *
 * BlockTable[] (16 bytes per entry, rawOffset strictly ascending,
 * class-aligned — a class's records never straddle two blocks):
 *   +0  u32 rawOffset    relative offset in the virtual raw method-data space,
 *                        same space as ClassIndexEntry.methodDataOff
 *   +4  u32 rawSize      uncompressed size of this block
 *   +8  u32 compOffset   absolute offset from the payload start
 *   +12 u32 compSize     ciphertext size
 *
 * Blocks[]: ChaCha20(aesKey, nonce = blockIdx, rawDeflate(plaintext records))
 *
 * Method records (inside a block, after decryption; format unchanged from v4
 * except the insns are PLAINTEXT):
 *   u32 methodIdx
 *   u16 insnsSize          <-- BYTE count, not code-unit count
 *   u8[insnsSize] insns
 * </pre>
 *
 * <p>The "virtual raw method-data space" is the layout v4 would have produced
 * for the same classes: records laid out in ClassIndex order, offsets relative
 * to zero. The runtime maps a class's {@code methodDataOff} onto its block and
 * walks records inside the inflated buffer, so the v4 record-walk logic is
 * reused verbatim.
 *
 * <p><b>Why blocks.</b> The payload is ChaCha20 ciphertext, which is
 * incompressible — v4 paid full price for every instruction byte. Compressing
 * the records first (they are highly repetitive dex bytecode, ~50% ratio) and
 * encrypting afterwards gives the size win back; blocks keep the runtime's
 * random-access property (one small inflate per class-load instead of one
 * whole-payload inflate at init).
 *
 * <p><b>Method order contract (unchanged from v4).</b> Within one class,
 * entries follow the order produced by {@code ClassData.allMethods()}, i.e.
 * direct methods first, then virtual methods. The runtime's {@code patchClass}
 * parses ClassData in exactly that order. {@code MultiDexCodeUtils} keeps this
 * order verbatim; changing it would make the runtime restore method A's
 * instructions into method B's body.
 */
public class MultiDexCode {

    public short getVersion() {
        return version;
    }

    public void setVersion(short version) {
        this.version = version;
    }

    public short getDexCount() {
        return dexCount;
    }

    public void setDexCount(short dexCount) {
        this.dexCount = dexCount;
    }

    public int getClassIndexOffset() {
        return classIndexOffset;
    }

    public void setClassIndexOffset(int classIndexOffset) {
        this.classIndexOffset = classIndexOffset;
    }

    public int getBlockTableOffset() {
        return blockTableOffset;
    }

    public void setBlockTableOffset(int blockTableOffset) {
        this.blockTableOffset = blockTableOffset;
    }

    public int getBlockCount() {
        return blockCount;
    }

    public void setBlockCount(int blockCount) {
        this.blockCount = blockCount;
    }

    public List<ClassIndexEntry> getClassIndex() {
        return classIndex;
    }

    public void setClassIndex(List<ClassIndexEntry> classIndex) {
        this.classIndex = classIndex;
    }

    public List<BlockTableEntry> getBlockTable() {
        return blockTable;
    }

    public void setBlockTable(List<BlockTableEntry> blockTable) {
        this.blockTable = blockTable;
    }

    /**
     * One compressed+encrypted block per entry of the block table, in table
     * order.
     */
    public List<byte[]> getBlocks() {
        return blocks;
    }

    public void setBlocks(List<byte[]> blocks) {
        this.blocks = blocks;
    }

    //File version
    private short version;
    //Dex count
    private short dexCount;
    //Offset of ClassIndex[] from the start of the payload
    private int classIndexOffset;
    //Offset of BlockTable[] from the start of the payload
    private int blockTableOffset;
    //Number of BlockTable[] entries
    private int blockCount;
    //Per-class index, sorted by (dexIdx, classDataOff)
    private List<ClassIndexEntry> classIndex;
    //Block table: raw span -> compressed block (one entry per block)
    private List<BlockTableEntry> blockTable;
    //Compressed+encrypted record blocks, in BlockTable order
    private List<byte[]> blocks;
}
