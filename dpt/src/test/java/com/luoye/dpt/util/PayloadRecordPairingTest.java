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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 守住 v4 载荷最要命的那条契约：<b>打包侧遍历的每个方法都必须产出一条记录</b>。
 *
 * <p>这条契约是 1.0.1 崩溃的根因。v4 把「密文 ↔ 方法」的配对从「按 methodIdx
 * 索引寻址」改成了「按类内位置递增配对」，于是任何一个不产记录的方法都会把
 * 它<em>之后</em>的每个方法整体错位一格 —— 前一个方法的密文被写进后一个方法的
 * 方法体。ART 在 {@code ClassLinker::DefineClass} 里一边解密一边校验 dex，
 * 于是直接 VerifyError / SIGSEGV，表现为「打出来的 APK 一点都跑不起来」。
 *
 * <p>1.0.0 不会中招：它建 65536 槽的表并用 {@code codeItemVec->at(methodIdx)}
 * 取密文，缺一条记录只影响那一个 methodIdx 本身。
 *
 * <p>本测试不依赖真实 APK，直接按 {@code DexUtils.extractAllMethods} 的遍历
 * 顺序构造输入，把 runtime 的遍历规则复刻一遍，然后断言配对逐个对齐。
 */
public class PayloadRecordPairingTest {

    private static Instruction ins(int methodIdx, int classDataOff, int byteLen) {
        Instruction i = new Instruction();
        i.setMethodIndex(methodIdx);
        i.setClassDataOff(classDataOff);
        i.setInstructionDataSize(byteLen);
        byte[] d = new byte[byteLen];
        for (int k = 0; k < byteLen; k++) {
            d[k] = (byte) (methodIdx * 13 + k);
        }
        i.setInstructionsData(d);
        return i;
    }

    /**
     * 打包侧为「未保护的方法」补的占位记录：insnsSize = 0。
     *
     * <p>与 {@code DexUtils.placeholderInstruction} 的产物一致。
     */
    private static Instruction placeholder(int methodIdx, int classDataOff) {
        return ins(methodIdx, classDataOff, 0);
    }

    /**
     * 一个类在 dex 里的方法列表：direct 在前，virtual 在后。
     *
     * <p>这正是 native {@code patchClass} 的读取顺序（readUleb128 依次取
     * direct/virtual 数量后按序遍历），也是 {@code ClassData.allMethods()} 的顺序，
     * 两边必须一致。
     */
    private static List<Instruction> aClass(int classDataOff, int methodIdxBase, int... gaps) {
        List<Instruction> methods = new ArrayList<>();
        int idx = methodIdxBase;
        for (int gap : gaps) {
            for (int k = 0; k < gap; k++) {
                methods.add(ins(idx++, classDataOff, 8));
            }
        }
        return methods;
    }

    /** 复刻 native {@code MultiDexCode::findClassIndex} 的二分查找。 */
    private static ClassIndexEntry findClassIndex(List<ClassIndexEntry> ci,
                                                  int dexIdx, int classDataOff) {
        int lo = 0, hi = ci.size();
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            ClassIndexEntry e = ci.get(mid);
            boolean less = (e.dexIdx & 0xff) != dexIdx
                    ? (e.dexIdx & 0xff) < dexIdx
                    : Integer.compareUnsigned(e.classDataOff, classDataOff) < 0;
            if (less) lo = mid + 1; else hi = mid;
        }
        if (lo >= ci.size()) return null;
        ClassIndexEntry e = ci.get(lo);
        if ((e.dexIdx & 0xff) != dexIdx) return null;
        if (Integer.compareUnsigned(e.classDataOff, classDataOff) != 0) return null;
        return e;
    }

    /** 读回 payload 里第 recIdx 条记录的 methodIdx（记录头 6 字节：u32 + u16）。 */
    private static int recordMethodIdx(MultiDexCode payload, int recIdx) {
        ByteBuffer bb = ByteBuffer.wrap(payload.getMethodData().get(recIdx))
                .order(ByteOrder.LITTLE_ENDIAN);
        return bb.getInt(0);
    }

    /** 读回记录的数据长度。 */
    private static int recordDataLen(MultiDexCode payload, int recIdx) {
        ByteBuffer bb = ByteBuffer.wrap(payload.getMethodData().get(recIdx))
                .order(ByteOrder.LITTLE_ENDIAN);
        return bb.getShort(4) & 0xffff;
    }

    /** 某条记录在扁平 methodData 列表中的下标。 */
    private static int flatIndexOf(List<ClassIndexEntry> ci, ClassIndexEntry target) {
        int acc = 0;
        for (ClassIndexEntry e : ci) {
            if (e == target) return acc;
            acc += e.methodCount & 0xffff;
        }
        throw new AssertionError("entry not found in class index");
    }

    private static byte[] write(MultiDexCode c) throws Exception {
        File f = File.createTempFile("dpt-pairing", ".bin");
        f.deleteOnExit();
        MultiDexCodeUtils.writeMultiDexCode(f.getAbsolutePath(), c);
        return Files.readAllBytes(f.toPath());
    }

    // ------------------------------------------------------------------
    // 核心回归：模拟真实 dex 里出现过的形状
    // ------------------------------------------------------------------

    /**
     * 一个类里混着受保护方法与「跳过」的方法（abstract/native、
     * code_item 被共享、insns 为空……）。
     *
     * <p>只要打包侧为每个被遍历到的方法都产出一条记录（受保护的带密文，
     * 跳过的带 insnsSize=0 占位），runtime 的位置配对就必然逐个对齐。
     */
    @Test
    public void placeholderKeepsEveryMethodPairedWithItsOwnCiphertext() throws Exception {
        final int classDataOff = 0x400;

        // 类里的 6 个方法：#2 是 abstract（占位），#4 是共享 code_item（占位）。
        List<Instruction> walked = aClass(classDataOff, 100, 1, 1, 1, 1, 1, 1);
        List<Instruction> packed = new ArrayList<>();
        for (int i = 0; i < walked.size(); i++) {
            packed.add((i == 2 || i == 4) ? placeholder(walked.get(i).getMethodIndex(), classDataOff)
                    : walked.get(i));
        }

        Map<Integer, List<Instruction>> m = new HashMap<>();
        m.put(0, packed);

        MultiDexCode payload = MultiDexCodeUtils.makeMultiDexCode(m);
        ClassIndexEntry entry = findClassIndex(payload.getClassIndex(), 0, classDataOff);
        Assert.assertNotNull("类必须在索引里", entry);

        int recBase = flatIndexOf(payload.getClassIndex(), entry);

        // 复刻 patchClass：按 allMethods() 顺序逐个消费记录。
        for (int i = 0; i < walked.size(); i++) {
            int dexMethodIdx = walked.get(i).getMethodIndex();
            int recIdx = recBase + i;
            int recMethodIdx = recordMethodIdx(payload, recIdx);

            Assert.assertEquals(
                    "第 " + i + " 个方法配到了别人的密文 —— 这正是 1.0.1 崩溃的原因",
                    dexMethodIdx, recMethodIdx);
        }

        // 占位记录必须真的零长，否则 runtime 会往抽象方法里写东西。
        Assert.assertEquals("abstract 方法的记录应零长", 0,
                recordDataLen(payload, recBase + 2));
        Assert.assertEquals("共享 code_item 方法的记录应零长", 0,
                recordDataLen(payload, recBase + 4));
    }

    /**
     * 一个类里<em>所有</em>方法都被跳过（例如整个类都是 interface 的抽象方法）。
     *
     * <p>这种类必须仍然在 payload 里留下 methodCount 条占位记录。
     * 少了它，后面所有类的位置配对会整体前移。
     */
    @Test
    public void fullyUnprotectedClassStillEmitsOneRecordPerMethod() throws Exception {
        final int classDataOff = 0x900;

        List<Instruction> walked = aClass(classDataOff, 200, 3, 4);   // 7 个方法
        List<Instruction> packed = new ArrayList<>();
        for (Instruction i : walked) {
            packed.add(placeholder(i.getMethodIndex(), classDataOff));
        }

        Map<Integer, List<Instruction>> m = new HashMap<>();
        m.put(0, packed);

        MultiDexCode payload = MultiDexCodeUtils.makeMultiDexCode(m);
        ClassIndexEntry entry = findClassIndex(payload.getClassIndex(), 0, classDataOff);

        Assert.assertNotNull("全占位的类也必须进索引，否则 runtime 会错配后续类", entry);
        Assert.assertEquals("记录数必须等于方法数", walked.size(), entry.methodCount & 0xffff);

        int recBase = flatIndexOf(payload.getClassIndex(), entry);
        for (int i = 0; i < walked.size(); i++) {
            Assert.assertEquals("第 " + i + " 个方法配错", walked.get(i).getMethodIndex(),
                    recordMethodIdx(payload, recBase + i));
            Assert.assertEquals("占位记录必须零长", 0, recordDataLen(payload, recBase + i));
        }
    }

    /**
     * 多个 dex、多类交替时，配对依然按类对齐。
     *
     * <p>这条守住 1.0.1 的第二个 bug 面：一旦某个类少一条记录，
     * <b>后面所有类</b>的 methodDataOff 都会错位，影响面远超那一个类。
     */
    @Test
    public void misalignmentInOneClassDoesNotLeakIntoLaterClasses() throws Exception {
        List<Instruction> dex0 = new ArrayList<>();
        dex0.addAll(aClass(0x100, 10, 2, 3));    // 类A: 2+3=5 个方法
        dex0.addAll(aClass(0x500, 50, 4, 2));    // 类B: 4+2=6 个方法（含占位）
        dex0.addAll(aClass(0x900, 90, 3, 3));    // 类C: 3+3=6 个方法

        // 类B 的第 2 个方法跳过 → 占位
        Instruction victim = dex0.get(5 + 2);
        dex0.set(5 + 2, placeholder(victim.getMethodIndex(), victim.getClassDataOff()));

        Map<Integer, List<Instruction>> m = new HashMap<>();
        m.put(0, dex0);
        MultiDexCode payload = MultiDexCodeUtils.makeMultiDexCode(m);

        for (int[] spec : new int[][]{{0x100, 10, 5}, {0x500, 50, 6}, {0x900, 90, 6}}) {
            ClassIndexEntry e = findClassIndex(payload.getClassIndex(), 0, spec[0]);
            Assert.assertNotNull("类 @" + Integer.toHexString(spec[0]) + " 必须可查", e);
            Assert.assertEquals("类 @" + Integer.toHexString(spec[0]) + " 记录数",
                    spec[2], e.methodCount & 0xffff);

            int base = flatIndexOf(payload.getClassIndex(), e);
            for (int i = 0; i < spec[2]; i++) {
                Assert.assertEquals("类 @" + Integer.toHexString(spec[0])
                                + " 第 " + i + " 个方法配错",
                        spec[1] + i, recordMethodIdx(payload, base + i));
            }
        }
    }

    // ------------------------------------------------------------------
    // 占位记录本身的性质
    // ------------------------------------------------------------------

    /**
     * 占位记录长度必须是 6 字节（只有头，无数据）。
     *
     * <p>runtime 的 {@code getMethodData} 按 {@code 6 + insnsSize} 前进，
     * insnsSize=0 时正好落在下一条记录上。
     */
    @Test
    public void placeholderRecordIsHeaderOnly() throws Exception {
        Map<Integer, List<Instruction>> m = new HashMap<>();
        m.put(0, new ArrayList<>(java.util.Collections.singletonList(placeholder(7, 0x10))));

        MultiDexCode payload = MultiDexCodeUtils.makeMultiDexCode(m);
        byte[] b = write(payload);

        Assert.assertEquals("占位记录应为 6 字节", 6, payload.getMethodData().get(0).length);

        // 整份 payload：16 header + 16 index + 6 record
        Assert.assertEquals(16 + 16 + 6, b.length);
    }

    /**
     * 占位记录也必须带上 methodIdx。
     *
     * <p>runtime 的 {@code patchOneClassMethod} 会拿 record 的 methodIdx 和
     * dex 方法比对；不一致就跳过。虽然占位的 data 是空的、根本不会走到那次比对，
     * 但带上正确的 methodIdx 让「这条记录属于谁」在 payload 里始终是自描述的。
     */
    @Test
    public void placeholderStillCarriesItsMethodIdx() throws Exception {
        Map<Integer, List<Instruction>> m = new HashMap<>();
        m.put(0, new ArrayList<>(java.util.Collections.singletonList(placeholder(4242, 0x20))));

        MultiDexCode payload = MultiDexCodeUtils.makeMultiDexCode(m);
        Assert.assertEquals(4242, recordMethodIdx(payload, 0));
    }

    /**
     * 载荷体积影响：占位记录只有 6 字节，补它们几乎不增加包大小。
     *
     * <p>这是选「打包侧补占位」而非「回退整个 v4 格式」的理由之一。
     */
    @Test
    public void placeholdersAreCheap() throws Exception {
        final int classDataOff = 0x80;
        List<Instruction> many = new ArrayList<>();
        for (int i = 0; i < 1000; i++) {
            many.add(placeholder(i, classDataOff));
        }

        Map<Integer, List<Instruction>> m = new HashMap<>();
        m.put(0, many);
        MultiDexCode payload = MultiDexCodeUtils.makeMultiDexCode(m);

        Assert.assertEquals(1000, (payload.getClassIndex().get(0).methodCount & 0xffff));
        Assert.assertEquals("1000 条占位 = 6000 字节载荷", 1000 * 6,
                payload.getMethodData().size() * 6);
    }

    // ------------------------------------------------------------------
    // 格式本身没被这次改动破坏
    // ------------------------------------------------------------------

    /** 这次改动不能动 header 布局 —— runtime 的 init 会先校验 magic 和 version。 */
    @Test
    public void headerLayoutUnchangedByPlaceholders() throws Exception {
        List<Instruction> methods = new ArrayList<>();
        methods.add(ins(1, 0x30, 8));
        methods.add(placeholder(2, 0x30));

        Map<Integer, List<Instruction>> m = new HashMap<>();
        m.put(0, methods);

        MultiDexCode payload = MultiDexCodeUtils.makeMultiDexCode(m);
        byte[] b = write(payload);
        ByteBuffer bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);

        Assert.assertEquals(Const.MULTI_DEX_CODE_MAGIC, bb.getInt(0));
        Assert.assertEquals(4, bb.getShort(4) & 0xffff);
        Assert.assertEquals(1, bb.getShort(6) & 0xffff);
        Assert.assertEquals(Const.MULTI_DEX_CODE_HEADER_SIZE, bb.getInt(8));
        Assert.assertEquals(Const.MULTI_DEX_CODE_HEADER_SIZE + 16, bb.getInt(12));
    }
}