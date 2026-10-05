package com.luoye.dpt.model;

import java.util.List;

/**
 * OoooooOooo payload, v4 layout.
 *
 * <pre>
 * Header (16 bytes)
 *   u32 magic = 0x4F4F4F34 ("OOO4")
 *   u16 version = 4
 *   u16 dexCount
 *   u32 classIndexOffset
 *   u32 methodDataOffset
 *
 * ClassIndex[] (16 bytes per entry, sorted by (dexIdx, classDataOff) unsigned ascending)
 *   +0  u8  dexIdx
 *   +1  u8  flags        reserved, written 0
 *   +2  u16 methodCount
 *   +4  u32 classDataOff
 *   +8  u32 methodDataOff  relative to methodDataOffset
 *   +12 u32 reserved       written 0
 *
 * MethodData[] (variable length, entries laid out in ClassIndex order)
 *   u32 methodIdx
 *   u16 insnsSize          <-- BYTE count, not code-unit count
 *   u8[insnsSize] encryptedInsns
 * </pre>
 *
 * <p>The class index is what replaces the runtime's old 65536-entry per-dex
 * table: a class is located with one binary search instead of a probe.
 *
 * <p><b>Method order contract.</b> Within one class, entries follow the order
 * produced by {@code ClassData.allMethods()}, i.e. direct methods first, then
 * virtual methods. The runtime's {@code patchClass} parses ClassData in exactly
 * that order, so {@code getMethodData(entry, i)} lines up with its i-th method.
 * {@code MultiDexCodeUtils} keeps this order verbatim; changing it would make the
 * runtime decrypt method A's ciphertext into method B's body.
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

    public int getMethodDataOffset() {
        return methodDataOffset;
    }

    public void setMethodDataOffset(int methodDataOffset) {
        this.methodDataOffset = methodDataOffset;
    }

    public List<ClassIndexEntry> getClassIndex() {
        return classIndex;
    }

    public void setClassIndex(List<ClassIndexEntry> classIndex) {
        this.classIndex = classIndex;
    }

    /**
     * One fully-encoded MethodData record per method, in the same order as the
     * owning ClassIndexEntry's methods.
     */
    public List<byte[]> getMethodData() {
        return methodData;
    }

    public void setMethodData(List<byte[]> methodData) {
        this.methodData = methodData;
    }

    //File version
    private short version;
    //Dex count
    private short dexCount;
    //Offset of ClassIndex[] from the start of the payload
    private int classIndexOffset;
    //Offset of MethodData[] from the start of the payload
    private int methodDataOffset;
    //Per-class index, sorted by (dexIdx, classDataOff)
    private List<ClassIndexEntry> classIndex;
    //Encoded MethodData records
    private List<byte[]> methodData;
}