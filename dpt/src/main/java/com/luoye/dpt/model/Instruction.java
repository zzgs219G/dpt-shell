package com.luoye.dpt.model;

import java.util.Arrays;

/**
 * @author luoyesiqiu
 */
public class Instruction {

    public int getMethodIndex() {
        return methodIndex;
    }

    public void setMethodIndex(int methodIndex) {
        this.methodIndex = methodIndex;
    }

    public int getInstructionDataSize() {
        return instructionDataSize;
    }

    public void setInstructionDataSize(int instructionDataSize) {
        this.instructionDataSize = instructionDataSize;
    }

    public byte[] getInstructionsData() {
        return instructionsData;
    }

    public void setInstructionsData(byte[] instructionsData) {
        this.instructionsData = instructionsData;
    }

    /**
     * Offset of this method's owning class's class_data_item within its dex.
     *
     * Required by the v4 OoooooOooo layout: the runtime looks a class up by
     * (dexIdx, classDataOff) instead of probing a per-dex table, so every
     * instruction has to carry its class's offset.
     *
     * <p>This is a signed int on purpose — it mirrors {@code ClassDef.getClassDataOffset()}
     * in dexlib2 and is written/read as an unsigned uint32. See
     * {@link Integer#toUnsignedLong(long)} in MultiDexCodeUtils when sorting.
     */
    public int getClassDataOff() {
        return classDataOff;
    }

    public void setClassDataOff(int classDataOff) {
        this.classDataOff = classDataOff;
    }

    @Override
    public String toString() {
        return "Instruction{" +
                "methodIndex=" + methodIndex +
                ", classDataOff=" + classDataOff +
                ", instructionDataSize=" + instructionDataSize +
                ", instructionsData=" + Arrays.toString(instructionsData) +
                '}';
    }


    //Corresponding method_idx in dex
    private int methodIndex;
    //class_data_off of the owning class (v4 payload index key)
    private int classDataOff;
    //instructionsData size
    private int instructionDataSize;
    //insns data
    private byte[] instructionsData;
}
