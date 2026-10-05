package com.luoye.dpt.model;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * One entry of the v4 OoooooOooo class index: where a class's methods live
 * inside the MethodData block.
 */
public class ClassIndexEntry {

    public byte dexIdx;
    public byte flags;          // reserved, written 0
    public short methodCount;
    public int classDataOff;
    public int methodDataOff;   // relative to the payload's methodDataOffset
    public int reserved;        // written 0, ignored on read

    public ClassIndexEntry() {
    }

    public ClassIndexEntry(byte dexIdx, short methodCount, int classDataOff, int methodDataOff) {
        this.dexIdx = dexIdx;
        this.flags = 0;
        this.methodCount = methodCount;
        this.classDataOff = classDataOff;
        this.methodDataOff = methodDataOff;
        this.reserved = 0;
    }

    /**
     * Serialize to the fixed 16-byte little-endian layout.
     *
     * <p>Layout is fixed rather than minimal (the fields would fit in 12 bytes)
     * so the native side can index the array directly with a fixed stride.
     */
    public byte[] toBytes() {
        ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        buf.put(dexIdx);
        buf.put(flags);
        buf.putShort(methodCount);
        buf.putInt(classDataOff);
        buf.putInt(methodDataOff);
        buf.putInt(reserved);
        return buf.array();
    }

    @Override
    public String toString() {
        return "ClassIndexEntry{" +
                "dexIdx=" + (dexIdx & 0xff) +
                ", methodCount=" + (methodCount & 0xffff) +
                ", classDataOff=" + classDataOff +
                ", methodDataOff=" + methodDataOff +
                '}';
    }
}