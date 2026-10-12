package com.luoye.dpt.util;

import com.luoye.dpt.config.Const;
import com.luoye.dpt.config.ShellConfig;
import com.luoye.dpt.model.BlockTableEntry;
import com.luoye.dpt.model.ClassIndexEntry;
import com.luoye.dpt.model.Instruction;
import com.luoye.dpt.model.MultiDexCode;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * Builds and writes the xixin_data payload.
 *
 * <p>Task 1.1 moved the format from v3 (a per-dex offset table plus a flat run
 * of code items) to v4 (header + per-class index + variable-length method
 * records). v5 keeps the v4 class index and record format but stores the
 * records in class-aligned compressed blocks: raw-DEFLATE first, then ChaCha20
 * per block (nonce = block index). The runtime's
 * {@code MultiDexCode::findClassIndex} binary-searches the index unchanged,
 * then materializes the one block holding the requested class.
 */
public class MultiDexCodeUtils {

    /**
     * Write buffer for xixin_data. Large enough that a typical payload is written
     * with a handful of flushes; small enough to stay off the large-object heap.
     */
    private static final int WRITE_BUFFER_SIZE = 64 * 1024;

    /**
     * Sort key for the class index.
     *
     * <p>{@code classDataOff} comes from dexlib2 as a signed {@code int} and can
     * legitimately exceed {@link Integer#MAX_VALUE} on a large dex. The runtime
     * reads it as {@code uint32_t}, so ordering must be unsigned on this side
     * too — a signed compare would sort those entries before small offsets and
     * break the binary search.
     */
    private static final Comparator<ClassIndexEntry> CLASS_INDEX_ORDER =
            Comparator.comparingInt((ClassIndexEntry e) -> e.dexIdx & 0xff)
                       .thenComparingLong(e -> Integer.toUnsignedLong(e.classDataOff));

    /**
     * Build a v5 payload from the extracted instructions, keyed by dex index.
     *
     * @param multiDexInsns dex index -> that dex's protected methods, in
     *                      {@code ClassData.allMethods()} order
     */
    public static MultiDexCode makeMultiDexCode(Map<Integer, List<Instruction>> multiDexInsns) {
        MultiDexCode multiDexCode = new MultiDexCode();
        multiDexCode.setVersion(Const.MULTI_DEX_CODE_VERSION);
        multiDexCode.setDexCount((short) multiDexInsns.size());
        multiDexCode.setClassIndexOffset(Const.MULTI_DEX_CODE_HEADER_SIZE);

        // Group every instruction under its (dexIdx, classDataOff) pair, preserving
        // the incoming method order inside each group.
        List<ClassIndexEntry> classIndex = new ArrayList<>();
        List<List<byte[]>> recordsPerClass = new ArrayList<>();

        multiDexInsns.entrySet().stream()
                .filter(e -> e.getValue() != null && !e.getValue().isEmpty())
                .sorted(Comparator.comparingInt(Map.Entry::getKey))
                .forEach(entry -> {
                    int dexIdx = entry.getKey();
                    for (List<Instruction> byClass : groupByClass(entry.getValue())) {
                        ClassIndexEntry cie = new ClassIndexEntry();
                        cie.dexIdx = (byte) dexIdx;
                        cie.flags = 0;
                        cie.methodCount = (short) byClass.size();
                        cie.classDataOff = byClass.get(0).getClassDataOff();
                        cie.reserved = 0;
                        cie.methodDataOff = 0;   // assigned below, after sorting
                        classIndex.add(cie);

                        List<byte[]> block = new ArrayList<>(byClass.size());
                        for (Instruction ins : byClass) {
                            block.add(encodeMethodData(ins));
                        }
                        recordsPerClass.add(block);
                    }
                });

        // The runtime binary-searches ClassIndex, so entries must be sorted by
        // (dexIdx, classDataOff). Sorting the index alone would desynchronise every
        // methodDataOff, so the per-class records are permuted alongside it.
        List<ClassIndexEntry> sortedIndex = new ArrayList<>(classIndex.size());
        List<List<byte[]>> sortedRecordsPerClass = new ArrayList<>();
        for (int i : order(classIndex.size(), classIndex, recordsPerClass)) {
            sortedIndex.add(classIndex.get(i));
            sortedRecordsPerClass.add(recordsPerClass.get(i));
        }

        // Assign relative offsets now that the record order is fixed. These are
        // offsets in the *virtual raw* method-data space: records laid out
        // contiguously in sortedIndex order, exactly as v4 stored them. v5
        // keeps the virtual addresses and stores the bytes compressed+encrypted
        // in blocks.
        int offset = 0;
        int recordIndex = 0;
        for (ClassIndexEntry cie : sortedIndex) {
            cie.methodDataOff = offset;
            for (byte[] rec : sortedRecordsPerClass.get(recordIndex++)) {
                offset += rec.length;
            }
        }

        // Partition the classes into class-aligned blocks, then compress and
        // encrypt each block. A class's records never straddle a block boundary,
        // so one materialized block covers a whole patchClass walk on the
        // runtime side.
        byte[] aesKey = ShellConfig.getInstance().getInsnsCryptKey();
        List<byte[]> compBlocks = new ArrayList<>();
        List<BlockTableEntry> blockTable = new ArrayList<>();
        partitionAndCompress(sortedIndex, sortedRecordsPerClass, aesKey,
                blockTable, compBlocks);

        // Assign absolute ciphertext offsets: Blocks[] starts right after the
        // block table. appendBlock left compOffset = 0 because blockCount (and
        // therefore blocksStart) was not known until the partition finished.
        int blocksStart = Const.MULTI_DEX_CODE_HEADER_SIZE
                + sortedIndex.size() * Const.MULTI_DEX_CODE_CLASS_INDEX_ENTRY_SIZE
                + blockTable.size() * Const.MULTI_DEX_CODE_BLOCK_ENTRY_SIZE;
        int compCursor = blocksStart;
        for (BlockTableEntry e : blockTable) {
            e.compOffset = compCursor;
            compCursor += e.compSize;
        }

        multiDexCode.setBlockTableOffset(Const.MULTI_DEX_CODE_HEADER_SIZE
                + sortedIndex.size() * Const.MULTI_DEX_CODE_CLASS_INDEX_ENTRY_SIZE);
        multiDexCode.setBlockCount(blockTable.size());
        multiDexCode.setClassIndex(sortedIndex);
        multiDexCode.setBlockTable(blockTable);
        multiDexCode.setBlocks(compBlocks);
        return multiDexCode;
    }

    /**
     * Permutation [0..n) sorting by (dexIdx, classDataOff).
     */
    private static List<Integer> order(int n,
                                       List<ClassIndexEntry> classIndex,
                                       List<List<byte[]>> recordsPerClass) {
        List<Integer> order = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            order.add(i);
        }
        order.sort(Comparator
                .comparing((Integer i) -> classIndex.get(i), CLASS_INDEX_ORDER)
                .thenComparingInt(i -> i));
        return order;
    }

    /**
     * Walk the sorted classes, accumulating plaintext records into blocks of
     * ~{@link Const#MULTI_DEX_CODE_BLOCK_TARGET_SIZE} raw bytes, and append one
     * compressed+encrypted block per partition.
     *
     * <p>Blocks are closed on class boundaries only: a class's records always
     * land in a single block, which keeps the runtime's cache simple (one
     * materialized block covers a whole class walk).
     */
    private static void partitionAndCompress(List<ClassIndexEntry> sortedIndex,
                                             List<List<byte[]>> sortedRecordsPerClass,
                                             byte[] aesKey,
                                             List<BlockTableEntry> blockTable,
                                             List<byte[]> compBlocks) {
        if (sortedIndex.isEmpty()) {
            return;
        }

        ByteArrayOutputStream rawBuf = new ByteArrayOutputStream(
                Const.MULTI_DEX_CODE_BLOCK_TARGET_SIZE);
        int blockRawOffset = sortedIndex.get(0).methodDataOff;
        int blockRawSize = 0;
        int recordCursor = 0;

        for (ClassIndexEntry cie : sortedIndex) {
            for (byte[] rec : sortedRecordsPerClass.get(recordCursor++)) {
                rawBuf.write(rec, 0, rec.length);
                blockRawSize += rec.length;
            }
            if (blockRawSize >= Const.MULTI_DEX_CODE_BLOCK_TARGET_SIZE) {
                blockRawOffset = appendBlock(blockTable, compBlocks, blockIdx(blockTable),
                        blockRawOffset, blockRawSize, rawBuf, aesKey);
                blockRawSize = 0;
                rawBuf.reset();
            }
        }
        if (blockRawSize > 0) {
            appendBlock(blockTable, compBlocks, blockIdx(blockTable),
                    blockRawOffset, blockRawSize, rawBuf, aesKey);
        }
    }

    private static int blockIdx(List<BlockTableEntry> blockTable) {
        return blockTable.size();
    }

    /**
     * Compress + encrypt one block and append it. Records are contiguous in the
     * virtual raw space, so the next block starts at
     * {@code rawOffset + rawSize}.
     *
     * @return the next block's rawOffset
     */
    private static int appendBlock(List<BlockTableEntry> blockTable,
                                   List<byte[]> compBlocks,
                                   int blockIdx,
                                   int blockRawOffset,
                                   int blockRawSize,
                                   ByteArrayOutputStream rawBuf,
                                   byte[] aesKey) {
        byte[] comp = compressBlock(rawBuf.toByteArray(), aesKey, blockIdx);
        blockTable.add(new BlockTableEntry(blockRawOffset, blockRawSize, 0, comp.length));
        compBlocks.add(comp);
        return blockRawOffset + blockRawSize;
    }

    /**
     * Raw-DEFLATE one block of plaintext records, then ChaCha20-encrypt it with
     * nonce = {@code blockIdx} (same derivation the runtime uses to decrypt:
     * {@code build_chacha20_nonce(blockIdx)}).
     *
     * <p>Encryption happens after compression on purpose — the whole point of
     * v5. The ciphertext length equals the deflated length (stream cipher), so
     * the block table's compSize is exact.
     */
    private static byte[] compressBlock(byte[] rawRecords, byte[] aesKey, int blockIdx) {
        byte[] deflated = CryptoUtils.deflateRaw(rawRecords);
        byte[] nonce = CryptoUtils.buildChaCha20Nonce(blockIdx);
        byte[] encrypted = CryptoUtils.chacha20Crypt(aesKey, nonce, deflated);
        if (encrypted == null || encrypted.length != deflated.length) {
            throw new IllegalStateException("block chacha20 encrypt failed");
        }
        return encrypted;
    }

    /**
     * Group consecutive instructions that belong to the same class.
     *
     * <p>Consecutive grouping (rather than a hash map) is deliberate: the caller
     * emits one class's methods at a time, in class order, so a run of equal
     * {@code classDataOff} is exactly one class. That keeps the method order the
     * runtime expects without needing to sort methods by index, which would
     * destroy the direct-then-virtual ordering contract.
     */
    private static List<List<Instruction>> groupByClass(List<Instruction> insns) {
        List<List<Instruction>> groups = new ArrayList<>();
        List<Instruction> current = null;
        int currentOff = 0;
        for (Instruction ins : insns) {
            if (current == null || ins.getClassDataOff() != currentOff) {
                current = new ArrayList<>();
                groups.add(current);
                currentOff = ins.getClassDataOff();
            }
            current.add(ins);
        }
        return groups;
    }

    /**
     * Encode one MethodData record.
     *
     * <p>{@code insnsSize} is the <b>byte</b> count, matching
     * {@code Instruction.getInstructionDataSize()} and the runtime's
     * {@code MultiDexCode::getMethodData}, which advances by
     * {@code 6 + insnsSize}. Storing the code-unit count here would make the
     * runtime read twice as far and land mid-record.
     *
     * <p>v5: {@code ins.getInstructionsData()} holds <b>plaintext</b> insns.
     * Encryption is per-block ({@link #compressBlock}); v4 encrypted per method
     * here, which made the payload incompressible.
     */
    private static byte[] encodeMethodData(Instruction ins) {
        byte[] data = ins.getInstructionsData();
        ByteBuffer buf = ByteBuffer.allocate(6 + data.length).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(ins.getMethodIndex());
        buf.putShort((short) data.length);
        buf.put(data);
        return buf.array();
    }

    /**
     * Write the payload out in the v5 layout: header, ClassIndex[], BlockTable[],
     * Blocks[]. Everything is little-endian; the runtime reads these fields
     * straight out of mapped memory.
     */
    public static void writeMultiDexCode(String out, MultiDexCode multiDexCode) {
        if (multiDexCode.getClassIndex() == null || multiDexCode.getClassIndex().isEmpty()
                || multiDexCode.getBlockTable() == null || multiDexCode.getBlockTable().isEmpty()) {
            return;
        }

        OutputStream bufferedOut = null;
        try {
            bufferedOut = new BufferedOutputStream(
                    new FileOutputStream(out), WRITE_BUFFER_SIZE);

            // Header (24 bytes)
            bufferedOut.write(Endian.makeLittleEndian(Const.MULTI_DEX_CODE_MAGIC));
            bufferedOut.write(Endian.makeLittleEndian(multiDexCode.getVersion()));
            bufferedOut.write(Endian.makeLittleEndian(multiDexCode.getDexCount()));
            bufferedOut.write(Endian.makeLittleEndian(multiDexCode.getClassIndexOffset()));
            bufferedOut.write(Endian.makeLittleEndian(multiDexCode.getBlockTableOffset()));
            bufferedOut.write(Endian.makeLittleEndian(multiDexCode.getBlockCount()));
            bufferedOut.write(Endian.makeLittleEndian(0));

            for (ClassIndexEntry entry : multiDexCode.getClassIndex()) {
                bufferedOut.write(entry.toBytes());
            }
            for (BlockTableEntry entry : multiDexCode.getBlockTable()) {
                bufferedOut.write(entry.toBytes());
            }
            for (byte[] block : multiDexCode.getBlocks()) {
                bufferedOut.write(block);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            IoUtils.close(bufferedOut);
        }
    }
}
