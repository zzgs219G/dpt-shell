package com.luoye.dpt.util;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.zip.CRC32;

/**
 * SoSectionLocker.java —— 构建期把 so 的 .bitcode 段用派生链加密
 *
 * 【为什么在构建期做】
 *   运行期 C 侧（dpt_keyladder.c）从 APK 证书派生 key 解密 .bitcode。
 *   打包侧必须用【同一把 key】加密，否则解不开。
 *
 * 【key 怎么做到两侧一致】
 *   key = HKDF(master, SHA256(certDER), "dpt-sec-v1"+pkg)
 *   master = SHA256(DPT_KL_SEED || CRC32(.text) || "dpt-kl-v1")
 *
 *   三个输入的来源：
 *     · DPT_KL_SEED   root build.gradle 生成并持久化，shell/build.gradle 传给
 *                     CMake（4 个 ABI 同一把），并落盘到 shell-files/
 *                     keyladder-seed.txt；本类从该文件读。
 *     · CRC32(.text)  链接后即固定（--gc-sections 是链接期动作，之后
 *                     AGP 的 strip 只删 .symtab/.debug_*，不动 .text）。
 *                     本类直接读 so 文件的 .text 段算，与运行期 C 侧
 *                     dpt_keyladder.c 的 ELF 解析同源。
 *     · certDER/pkg   由调用方从 APK 提（打包时输入 APK 已知）。
 *
 * ⚠️ 为什么用证书而不是 keystore：
 *   keystore 是"将要用来签名的钥匙"，而运行期设备上安装的是"已签名的 APK"。
 *   两者可能不同（本仓库契约是产出未签名包，开发者自行重签）。
 *   所以必须用【输入 APK 里已有的证书】，这才与运行期读到的一致。
 *
 * ⚠️ size-preserving：加密后段长不变（ELF 段大小固定，运行期原地解密）。
 */
public final class SoSectionLocker {

    private SoSectionLocker() {}

    /** 与 C 侧 SECTION_NAME_BITCODE 一致。 */
    public static final String BITCODE_SECTION = ".bitcode";

    /**
     * 把 so 的 .bitcode 段用派生链加密（原地等长覆写）。
     *
     * @param soFile   待加密的 so（会被原地修改）
     * @param seed     编译期种子（CMake 的 DPT_KL_SEED 数值，16 位 hex 字符串）
     * @param certDer  APK 第一签名者证书 DER
     * @param pkg      应用包名
     * @return 加密是否发生（false = 没有 .bitcode 段，无需加密）
     */
    public static boolean lockBitcode(File soFile, String seed, byte[] certDer, String pkg)
            throws IOException {
        byte[] data = readAll(soFile);
        Section sec = findSection(data, BITCODE_SECTION);
        if (sec == null) {
            System.out.println("[lock] " + soFile.getName() + ": 无 " + BITCODE_SECTION + " 段，跳过");
            return false;
        }

        long seedVal = Long.parseUnsignedLong(seed, 16);
        byte[] plain = Arrays.copyOfRange(data, sec.offset, sec.offset + sec.size);
        long textCrc = crc32OfText(data);
        byte[] key = KeyLadder.deriveKey(seedVal, textCrc, certDer, pkg);
        byte[] enc = CryptoUtils.rc4Crypt(key, plain);

        if (enc.length != plain.length) {
            throw new IllegalStateException("RC4 不是 size-preserving: "
                    + plain.length + " → " + enc.length);
        }
        System.arraycopy(enc, 0, data, sec.offset, enc.length);
        writeAll(soFile, data);

        System.out.println("[lock] " + soFile.getName() + ": " + BITCODE_SECTION
                + " " + sec.size + " B 已加密（CRC32(.text)=0x"
                + Long.toHexString(textCrc) + "）");
        return true;
    }

    /* ── ELF 段定位 ───────────────────────────────────────────────── */

    private static final class Section {
        int offset;
        int size;
    }

    /**
     * 找命名段，返回其文件内 offset/size（找不到返回 null）。
     * 同时支持 ELF32 与 ELF64 —— armeabi-v7a 是 ELF32，漏了它会在
     * 32 位 ABI 上锁箱失败（本机实测踩过）。
     */
    private static Section findSection(byte[] elf, String name) {
        if (elf.length < 64 || elf[0] != 0x7f || elf[1] != 'E') return null;
        boolean is64 = elf[4] == 2;

        // ELF 头里 e_shoff/e_shentsize/e_shnum/e_shstrndx 的偏移在两种
        // 格式下不同，这是唯一需要分支的地方。
        long e_shoff;
        int e_shentsize, e_shnum, e_shstrndx;
        if (is64) {
            e_shoff = le64(elf, 0x28);
            e_shentsize = le16(elf, 0x3A);
            e_shnum = le16(elf, 0x3C);
            e_shstrndx = le16(elf, 0x3E);
        } else {
            e_shoff = le32(elf, 0x20) & 0xFFFFFFFFL;
            e_shentsize = le16(elf, 0x2E);
            e_shnum = le16(elf, 0x30);
            e_shstrndx = le16(elf, 0x32);
        }

        // 段头里 sh_name(4) / sh_addr / sh_offset / sh_size 的偏移同样分格式
        final int OFF_NAME, OFF_ADDR, OFF_OFFSET, OFF_SIZE;
        if (is64) {
            OFF_NAME = 0; OFF_ADDR = 0x10; OFF_OFFSET = 0x18; OFF_SIZE = 0x20;
        } else {
            OFF_NAME = 0; OFF_ADDR = 0x0C; OFF_OFFSET = 0x10; OFF_SIZE = 0x14;
        }

        // 段名表（.shstrtab）自身也在这张表里。
        // ⚠️ 必须用 sh_offset 而不是 sh_addr：.shstrtab 是非 ALLOC 段，
        //    它的 sh_addr 为 0（本机实测 arm64 产物就是 0）。用 sh_addr
        //    会得到偏移 0，于是所有段名都从文件头解析 → 全表匹配不上。
        long shstrHdr = e_shoff + (long) e_shstrndx * e_shentsize;
        long shstrAddr = readWord(elf, (int) shstrHdr + OFF_OFFSET, is64);

        for (int i = 0; i < e_shnum; i++) {
            long o = e_shoff + (long) i * e_shentsize;
            int nameOff = le32(elf, (int) o + OFF_NAME);
            long secOff = readWord(elf, (int) o + OFF_OFFSET, is64);
            long secSize = readWord(elf, (int) o + OFF_SIZE, is64);
            if (secSize == 0 || secSize > Integer.MAX_VALUE) continue;

            int np = (int) shstrAddr + nameOff;
            int end = np;
            while (end < elf.length && elf[end] != 0) end++;
            String nm = new String(elf, np, end - np, StandardCharsets.US_ASCII);
            if (nm.equals(name)) {
                Section s = new Section();
                s.offset = (int) secOff;
                s.size = (int) secSize;
                return s;
            }
        }
        return null;
    }

    /** 按 ELF 格式读一个字（ELF32=4 字节，ELF64=8 字节）。 */
    private static long readWord(byte[] d, int off, boolean is64) {
        return is64 ? le64(d, off) : (le32(d, off) & 0xFFFFFFFFL);
    }

    private static long crc32OfText(byte[] elf) {
        Section t = findSection(elf, ".text");
        if (t == null) throw new IllegalStateException("so 无 .text 段");
        CRC32 crc = new CRC32();
        crc.update(elf, t.offset, t.size);
        return crc.getValue();
    }

    /* ── 小工具 ──────────────────────────────────────────────────── */

    private static byte[] readAll(File f) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
            byte[] b = new byte[(int) raf.length()];
            raf.readFully(b);
            return b;
        }
    }

    private static void writeAll(File f, byte[] data) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
            raf.write(data);
        }
    }

    private static int le16(byte[] d, int o) {
        return (d[o] & 0xFF) | ((d[o + 1] & 0xFF) << 8);
    }

    private static int le32(byte[] d, int o) {
        return (d[o] & 0xFF) | ((d[o + 1] & 0xFF) << 8)
                | ((d[o + 2] & 0xFF) << 16) | ((d[o + 3] & 0xFF) << 24);
    }

    private static long le64(byte[] d, int o) {
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (d[o + i] & 0xFF);
        return v;
    }
}
