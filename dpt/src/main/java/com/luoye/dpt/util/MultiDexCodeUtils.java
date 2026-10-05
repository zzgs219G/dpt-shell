package com.luoye.dpt.util;

import com.luoye.dpt.config.Const;
import com.luoye.dpt.model.ClassIndexEntry;
import com.luoye.dpt.model.Instruction;
import com.luoye.dpt.model.MultiDexCode;

import java.io.BufferedOutputStream;
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
 * Builds and writes the OoooooOooo payload.
 *
 * <p>Task 1.1 moved the format from v3 (a per-dex offset table plus a flat run
 * of code items) to v4 (header + per-class index + variable-length method
 * records). The runtime's {@code MultiDexCode::findClassIndex} binary-searches
 * the index, so the entries must be sorted by {@code (dexIdx, classDataOff)}.
 */
public class MultiDexCodeUtils {

    /**
     * Write buffer for OoooooOooo. Large enough that a typical payload is written
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
     * Build a v4 payload from the extracted instructions, keyed by dex index.
     *
     * @param multiDexInsns dex index -&gt; that dex's protected methods, in
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
        List<List<byte[]>> blocksPerClass = new ArrayList<>();

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
                        blocksPerClass.add(block);
                    }
                });

        // The runtime binary-searches ClassIndex, so entries must be sorted by
        // (dexIdx, classDataOff). Sorting the index alone would desynchronise every
        // methodDataOff, so the per-class blocks are permuted alongside it.
        List<Integer> order = new ArrayList<>(classIndex.size());
        for (int i = 0; i < classIndex.size(); i++) {
            order.add(i);
        }
        order.sort(Comparator
                .comparing((Integer i) -> classIndex.get(i), CLASS_INDEX_ORDER)
                .thenComparingInt(i -> i));

        List<ClassIndexEntry> sortedIndex = new ArrayList<>(classIndex.size());
        List<byte[]> sortedMethodData = new ArrayList<>();
        for (int i : order) {
            sortedIndex.add(classIndex.get(i));
            sortedMethodData.addAll(blocksPerClass.get(i));
        }

        // Assign relative offsets now that the MethodData block order is fixed.
        int offset = 0;
        int recordIndex = 0;
        for (ClassIndexEntry cie : sortedIndex) {
            cie.methodDataOff = offset;
            for (int i = 0; i < (cie.methodCount & 0xffff); i++) {
                offset += sortedMethodData.get(recordIndex++).length;
            }
        }

        multiDexCode.setMethodDataOffset(
                Const.MULTI_DEX_CODE_HEADER_SIZE
                        + sortedIndex.size() * Const.MULTI_DEX_CODE_CLASS_INDEX_ENTRY_SIZE);
        multiDexCode.setClassIndex(sortedIndex);
        multiDexCode.setMethodData(sortedMethodData);
        return multiDexCode;
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
     * Write the payload out in v4 layout: header, ClassIndex[], MethodData[].
     *
     * <p>Everything is little-endian; the runtime reads these fields straight
     * out of mapped memory.
     */
    public static void writeMultiDexCode(String out, MultiDexCode multiDexCode) {
        if (multiDexCode.getClassIndex() == null || multiDexCode.getClassIndex().isEmpty()) {
            return;
        }

        OutputStream bufferedOut = null;
        try {
            bufferedOut = new BufferedOutputStream(
                    new FileOutputStream(out), WRITE_BUFFER_SIZE);

            bufferedOut.write(Endian.makeLittleEndian(Const.MULTI_DEX_CODE_MAGIC));
            bufferedOut.write(Endian.makeLittleEndian(multiDexCode.getVersion()));
            bufferedOut.write(Endian.makeLittleEndian(multiDexCode.getDexCount()));
            bufferedOut.write(Endian.makeLittleEndian(multiDexCode.getClassIndexOffset()));
            bufferedOut.write(Endian.makeLittleEndian(multiDexCode.getMethodDataOffset()));

            for (ClassIndexEntry entry : multiDexCode.getClassIndex()) {
                bufferedOut.write(entry.toBytes());
            }
            for (byte[] record : multiDexCode.getMethodData()) {
                bufferedOut.write(record);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            IoUtils.close(bufferedOut);
        }
    }
}