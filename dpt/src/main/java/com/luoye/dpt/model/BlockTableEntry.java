package com.luoye.dpt.model;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * One entry of the v5 xixin_data block table: which slice of the virtual raw
 * method-data space lives in which compressed+encrypted block.
 *
 * <p>rawOffset/rawSize describe the block's span in the same virtual space as
 * {@link ClassIndexEntry#methodDataOff}. compOffset is absolute (from the
 * payload start) so the runtime can read the ciphertext straight out of mapped
 * memory without re-deriving the blocks-region base.
 */
public class BlockTableEntry {

    public int rawOffset;
    public int rawSize;
    public int compOffset;
    public int compSize;

    public BlockTableEntry() {
    }

    public BlockTableEntry(int rawOffset, int rawSize, int compOffset, int compSize) {
        this.rawOffset = rawOffset;
        this.rawSize = rawSize;
        this.compOffset = compOffset;
        this.compSize = compSize;
    }

    /**
     * Serialize to the fixed 16-byte little-endian layout, so the native side
     * can index the array directly with a fixed stride (mirrors
     * {@link ClassIndexEntry#toBytes()}).
     */
    public byte[] toBytes() {
        ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(rawOffset);
        buf.putInt(rawSize);
        buf.putInt(compOffset);
        buf.putInt(compSize);
        return buf.array();
    }

    @Override
    public String toString() {
        return "BlockTableEntry{" +
                "rawOffset=" + rawOffset +
                ", rawSize=" + rawSize +
                ", compOffset=" + compOffset +
                ", compSize=" + compSize +
                '}';
    }
}
