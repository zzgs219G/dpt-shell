package com.luoye.dpt.builder;


import com.alibaba.fastjson2.JSON;
import com.iyxan23.zipalignjava.ZipAlign;
import com.luoye.dpt.Dpt;
import com.luoye.dpt.config.Const;
import com.luoye.dpt.config.ProtectRules;
import com.luoye.dpt.config.ShellConfig;
import com.luoye.dpt.dex.JunkCodeGenerator;
import com.luoye.dpt.elf.ReadElf;
import com.luoye.dpt.model.Instruction;
import com.luoye.dpt.model.MultiDexCode;
import com.luoye.dpt.task.ThreadPool;
import com.luoye.dpt.util.CryptoUtils;
import com.luoye.dpt.util.DexUtils;
import com.luoye.dpt.util.FileUtils;
import com.luoye.dpt.util.HexUtils;
import com.luoye.dpt.util.IoUtils;
import com.luoye.dpt.util.KeyUtils;
import com.luoye.dpt.util.LogUtils;
import com.luoye.dpt.util.MultiDexCodeUtils;
import com.luoye.dpt.util.StringUtils;
import com.luoye.dpt.util.ZipUtils;

import net.lingala.zip4j.model.enums.CompressionMethod;

import org.apache.commons.lang3.tuple.Pair;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

public abstract class AndroidPackage {

    public static abstract class Builder {
        public String filePath = null;
        public String outputPath = null;
        public String packageName = null;
        public boolean debuggable = false;
        public boolean sign = true;
        public boolean appComponentFactory = true;
        public boolean dumpCode = false;
        public List<String> excludedAbi;
        public String rulesFilePath;
        public boolean keepClasses = false;
        public boolean smaller = false;
        public String protectConfigFile = null;
        public boolean verifySign = false;
        public int riskCheckFlags = 0;
        public boolean useInmemoryDex = false;
        public boolean plain = false;
        /* --extra-dex：要合并进壳 dex 的外部 dex（可为 null = 不合并） */
        public String extraDexPath = null;
        /* --stub-seed：字符串桩的密钥流种子（16 位 hex；null = 未启用联动） */
        public String stubSeed = null;
        /* --cert-source：段加密派生链用的证书来源 APK（null = 用 -f 输入） */
        public String certSourcePath = null;

        public Builder filePath(String path) {
            this.filePath = path;
            return this;
        }

        public Builder outputPath(String outputPath) {
            this.outputPath = outputPath;
            return this;
        }

        public Builder excludedAbi(List<String> excludedAbi) {
            this.excludedAbi = excludedAbi;
            return this;
        }

        public Builder packageName(String packageName) {
            this.packageName = packageName;
            return this;
        }

        public Builder smaller(boolean smaller) {
            this.smaller = smaller;
            return this;
        }

        public Builder protectConfigFile(String protectConfigFile) {
            this.protectConfigFile = protectConfigFile;
            return this;
        }

        public Builder verifySign(boolean verifySign) {
            this.verifySign = verifySign;
            return this;
        }

        public Builder riskCheckFlags(int riskCheckFlags) {
            this.riskCheckFlags = riskCheckFlags;
            return this;
        }

        public Builder useInmemoryDex(boolean useInmemoryDex) {
            this.useInmemoryDex = useInmemoryDex;
            return this;
        }

        public Builder plain(boolean plain) {
            this.plain = plain;
            return this;
        }

        public Builder extraDexPath(String extraDexPath) {
            this.extraDexPath = extraDexPath;
            return this;
        }

        public Builder stubSeed(String stubSeed) {
            this.stubSeed = stubSeed;
            return this;
        }

        public Builder certSourcePath(String certSourcePath) {
            this.certSourcePath = certSourcePath;
            return this;
        }

        public Builder debuggable(boolean debuggable) {
            this.debuggable = debuggable;
            return this;
        }

        public Builder sign(boolean sign) {
            this.sign = sign;
            return this;
        }

        public Builder dumpCode(boolean dumpCode) {
            this.dumpCode = dumpCode;
            return this;
        }

        public Builder appComponentFactory(boolean appComponentFactory) {
            this.appComponentFactory = appComponentFactory;
            return this;
        }

        public Builder rulesFile(String rulesFilePath) {
            this.rulesFilePath = rulesFilePath;
            return this;
        }

        public Builder keepClasses(boolean keepClasses) {
            this.keepClasses = keepClasses;
            return this;
        }

        public abstract AndroidPackage build();
    } // Builder

    private String filePath = null;
    private String packageName = null;
    private boolean debuggable = false;
    private boolean sign = true;
    private boolean appComponentFactory = true;
    private boolean dumpCode = false;
    private boolean smaller = false;
    private List<String> excludedAbi;
    private String outputPath = null;
    private String rulesFilePath = null;
    private boolean keepClasses = false;
    private String protectConfigFile;
    private boolean verifySign = false;
    private int riskCheckFlags = 0;
    private boolean useInmemoryDex = false;
    private boolean plain = false;
    /* --extra-dex：合并进壳 dex 的外部 dex 路径（null = 不合并，零行为变更） */
    private String extraDexPath = null;
    /* --stub-seed：字符串桩密钥流种子（16 位 hex；null = 未启用联动） */
    private String stubSeed = null;
    /* --cert-source：段加密派生链用的证书来源 APK（null = 用输入 APK） */
    private String certSourcePath = null;

    public AndroidPackage(Builder builder) {
        setFilePath(builder.filePath);
        setDebuggable(builder.debuggable);
        setAppComponentFactory(builder.appComponentFactory);
        setSign(builder.sign);
        setPackageName(builder.packageName);
        setDumpCode(builder.dumpCode);
        setExcludedAbi(builder.excludedAbi);
        setOutputPath(builder.outputPath);
        setRulesFilePath(builder.rulesFilePath);
        setKeepClasses(builder.keepClasses);
        setSmaller(builder.smaller);
        setProtectConfigFile(builder.protectConfigFile);
        setVerifySign(builder.verifySign);
        setRiskCheckFlags(builder.riskCheckFlags);
        setUseInmemoryDex(builder.useInmemoryDex);
        setPlain(builder.plain);
        setExtraDexPath(builder.extraDexPath);
        setStubSeed(builder.stubSeed);
        setCertSourcePath(builder.certSourcePath);
    }

    /**
     * Plain pack mode: no instruction extraction, all runtime risk checks
     * disabled. The risk-check flags are forced here so the config the
     * runtime reads always matches, regardless of what the CLI passed.
     */
    private void setPlain(boolean plain) {
        this.plain = plain;
        if (plain) {
            this.riskCheckFlags = Const.FLAG_DISABLE_FRIDA_DETECT
                    | Const.FLAG_DISABLE_CRC_DETECT
                    | Const.FLAG_DISABLE_ANTI_DEBUG;
        }
    }

    public boolean isPlain() {
        return plain;
    }

    public void setProtectConfigFile(String protectConfigFile) {
        this.protectConfigFile = protectConfigFile;
    }

    public String getProtectConfigFile() {
        return protectConfigFile;
    }

    public void setVerifySign(boolean verifySign) {
        this.verifySign = verifySign;
    }

    public boolean isVerifySign() {
        return verifySign;
    }

    public int getRiskCheckFlags() {
        return riskCheckFlags;
    }

    public void setRiskCheckFlags(int riskCheckFlags) {
        this.riskCheckFlags = riskCheckFlags;
    }

    public boolean isUseInmemoryDex() {
        return useInmemoryDex;
    }

    public void setUseInmemoryDex(boolean useInmemoryDex) {
        this.useInmemoryDex = useInmemoryDex;
    }

    public boolean isSmaller() {
        return smaller;
    }

    public void setSmaller(boolean smaller) {
        this.smaller = smaller;
    }

    private void setKeepClasses(boolean keepClasses) {
        this.keepClasses = keepClasses;
    }

    public boolean isKeepClasses() {
        return keepClasses;
    }

    private void setRulesFilePath(String rulesFilePath) {
        this.rulesFilePath = rulesFilePath;
    }

    public String getRulesFilePath() {
        return rulesFilePath;
    }

    public String getOutputPath() {
        return outputPath;
    }

    public void setOutputPath(String outputPath) {
        this.outputPath = outputPath;
    }

    public void setExcludedAbi(List<String> excludedAbi) {
        this.excludedAbi = excludedAbi;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public boolean isDebuggable() {
        return debuggable;
    }

    public void setDebuggable(boolean debuggable) {
        this.debuggable = debuggable;
    }

    public boolean isSign() {
        return sign;
    }

    public void setSign(boolean sign) {
        this.sign = sign;
    }

    public boolean isAppComponentFactory() {
        return appComponentFactory;
    }

    public void setAppComponentFactory(boolean appComponentFactory) {
        this.appComponentFactory = appComponentFactory;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public void setDumpCode(boolean dumpCode) {
        this.dumpCode = dumpCode;
    }

    public boolean isDumpCode() {
        return dumpCode;
    }

    /**
     * Combine the compressed dex file with the shell dex to create a new dex file.
     */
    protected void combineDexZipWithShellDex(String packageMainProcessPath) {
        try {
            File shellDexFile = new File(getProxyDexPath());
            File renameDexFile = new File(getRenameDexPath());

            ShellConfig shellConfig = ShellConfig.getInstance();

            boolean needRename = !org.apache.commons.lang3.StringUtils.isBlank(shellConfig.getShellPackageName())
                    && !Const.DEFAULT_SHELL_PACKAGE_NAME.equals(shellConfig.getShellPackageName());

            if(needRename) {
                DexUtils.renamePackageName(shellDexFile, renameDexFile, shellConfig.getSlashShellPackageName());
            }

            /* --extra-dex：把外部 dex 合并进【壳 dex】（不碰业务 dex）。
             *
             * 为什么在这里而不是 Apk.process 主流程：
             *   extractDexCode 之后再合并业务 dex 会读到 bogus opcode 0e00
             *   —— 那时业务 dex 的方法体已被 00 0e 填充覆盖，DexMerger 拒绝解析。
             *   而壳 dex（shell-files/dex/classes.dex）全程不参与抽空，
             *   它的方法体是完整合法的，能安全合并。
             *
             * 合并到 rename 产物（needRename 时）或原始壳 dex，取实际被读的那个：
             *   后续 unShellDexArray 读的就是这里的目标文件，两者必须一致。
             *
             * 不改 shell-files 里的共享文件：合并结果写到 WORK 临时副本，
             * 多进程/多次打包不互相污染。
             */
            File mergeTarget = needRename ? renameDexFile : shellDexFile;
            mergeTarget = mergeExtraDexIntoTempCopy(mergeTarget);
            if (needRename) {
                renameDexFile = mergeTarget;
            } else {
                shellDexFile = mergeTarget;
            }

            File originalDexZipFile = new File(getOutAssetsDir(packageMainProcessPath).getAbsolutePath() + File.separator + Const.KEY_DEXES_STORE_NAME);
            byte[] zipData = com.android.dex.util.FileUtils.readFile(originalDexZipFile);// Read the zip file as binary data
            byte[] unShellDexArray =  com.android.dex.util.FileUtils.readFile(!needRename ? shellDexFile : renameDexFile); // Read the dex file as binary data
            int zipDataLen = zipData.length;
            int unShellDexLen = unShellDexArray.length;
            LogUtils.info("Dexes zip file size: %s", zipDataLen);
            LogUtils.info("Proxy dex file size: %s", unShellDexLen);
            int totalLen = zipDataLen + unShellDexLen + 4;// An additional 4 bytes are added to store the length
            byte[] newDexBytes = new byte[totalLen]; // Allocate the new length

            // Add the shell code
            System.arraycopy(unShellDexArray, 0, newDexBytes, 0, unShellDexLen);// First, copy the dex content
            // Add the unencrypted zip data
            System.arraycopy(zipData, 0, newDexBytes, unShellDexLen, zipDataLen); // Then copy the APK content after the dex content
            // Add the length of the shell data
            System.arraycopy(FileUtils.intToByte(zipDataLen), 0, newDexBytes, totalLen - 4, 4);// The last 4 bytes are for the length

            // Modify the DEX file size header
            FileUtils.fixFileSizeHeader(newDexBytes);
            // Modify the DEX SHA1 header
            FileUtils.fixSHA1Header(newDexBytes);
            // Modify the DEX CheckSum header
            FileUtils.fixCheckSumHeader(newDexBytes);

            String targetDexFile = getDexDir(packageMainProcessPath) + File.separator + "classes.dex";


            File file = new File(targetDexFile);
            if (!file.exists()) {
                file.createNewFile();
            }

            // Output the new dex file
            try (FileOutputStream localFileOutputStream = new FileOutputStream(targetDexFile)) {
                localFileOutputStream.write(newDexBytes);
                localFileOutputStream.flush();
            }
            LogUtils.info("New Dex file generated: " + targetDexFile);
            // Delete the dex zip package
            FileUtils.deleteRecurse(originalDexZipFile);
            FileUtils.deleteRecurse(renameDexFile);
        }catch (Exception e){
            e.printStackTrace();
        }

    }

    private String getUnsignPackageName(String packageFileName){
        return FileUtils.getNewFileName(packageFileName,"unsign");
    }

    private String getUnzipalignPackageName(String packageFileName){
        return FileUtils.getNewFileName(packageFileName,"unzipalign");
    }

    private String getSignedPackageName(String packageFileName){
        return FileUtils.getNewFileName(packageFileName,"signed");
    }

    /**
     * Same HMAC-SHA256 key as native read_shell_config aes_key.
     */
    /**
     * 指令载荷（dex insns）的 ChaCha20 密钥。
     *
     * 【2026-10-27 改】原实现 = HMAC(encKey, pkg+"_"+buildKey)，
     * encKey 是打包期随机值，运行期从导出符号 DPT_UNKNOWN_DATA 取回。
     * P0 删掉该符号后，运行期只能拿到派生链材料 —— 于是这条链断了：
     * 打包用旧公式、运行期用新材料，dex 载荷块 native 侧 inflate 全失败
     * （真机日志：materializeBlock() block 12 inflate failed: comp=56269
     * raw=94408）。
     *
     * 现在改为与配置解密材料共用同一条派生链的前 32 字节（aes_key 部分）：
     *   material = HKDF(SHA256(seed||"dpt-cfg-master"), SHA256(certDER),
     *                   "dpt-cfg-v1"+pkg, 48)
     *   insnsKey = material[0..32]
     * 运行期 g_shell_config.aes_key 正是这 32 字节，两侧天然一致。
     *
     * ⚠️ 为什么与配置 aes_key 复用同一个 key 是可以接受的：
     *   两者都是"本包内的对称加密"，攻击者拿到一个就拿到另一个 —— 但
     *   拿到它们的前提都是先攻破派生链（需要证书 + seed + 包名），
     *   而 seed 不在 APK 里。真正的隔离点是派生链本身，不是这两把钥匙。
     *   若将来要做域分离，给 insns 单独一个 info 前缀即可，记得两侧同改。
     *
     * 参数 randomKey（旧 encKey）不再参与派生，保留仅为调用点签名兼容。
     */
    private byte[] deriveConfigAesKey(byte[] randomKey) {
        byte[] material = deriveConfigMaterial();
        byte[] insnsKey = Arrays.copyOfRange(material, 0, 32);
        Arrays.fill(material, (byte) 0);
        return insnsKey;
    }

    /**
     * 加密并写出 shell config。
     *
     * 【2026-10-27 改：配置解密材料改走证书派生链】
     * 旧方案用 HMAC(encKey, pkg+"_"+buildKey) 派生 aes_key、encKey 改两位做 iv，
     * 而 encKey 明文躺在导出符号 DPT_UNKNOWN_DATA 里。逆向实证的完整攻击链：
     *   readelf -sW --dyn-syms | grep DPT_UNKNOWN_DATA   → 得到 symbol value
     *   dd 读该地址 16 字节                               → encKey
     *   HMAC + AES-CBC 解 assets/xixin_config             → stub_seed 等
     * 5 步、无需 root/调试器/脱壳。
     *
     * 现在与 .bitcode 段密钥共用同一条派生链（同一 master、同一 salt），
     * 只用 info 前缀做域分离（"dpt-cfg-v1"）。产物里不再有任何配置密钥材料。
     *
     * 参数 key 保留仅为签名兼容（Apk/Aab 两个调用点），不再参与派生。
     */
    public void writeConfig(String packageDir, byte[] key) {
        File configFile = new File(getOutAssetsDir(packageDir).getAbsolutePath() + File.separator, Const.KEY_SHELL_CONFIG_STORE_NAME);
        ShellConfig shellConfig = ShellConfig.getInstance();
        String json = shellConfig.toJson();
        LogUtils.info("Write config: " + json);

        byte[] material = deriveConfigMaterial();
        byte[] aesKey = Arrays.copyOfRange(material, 0, 32);
        byte[] iv = Arrays.copyOfRange(material, 32, 48);
        Arrays.fill(material, (byte) 0);

        byte[] secData = CryptoUtils.aesEncrypt(aesKey, iv, json.getBytes(StandardCharsets.UTF_8));
        Arrays.fill(aesKey, (byte) 0);
        Arrays.fill(iv, (byte) 0);
        if (secData == null) {
            throw new IllegalStateException("encrypt shell config failed");
        }
        IoUtils.writeFile(configFile.getAbsolutePath(), secData);
    }

    /**
     * 派生配置解密材料：[aes_key(32) || iv(16)]，共 48 字节。
     *
     * 必须与运行期 dpt_kl_derive_config_material() 逐字节一致：
     *   master = SHA256(seed_8 || "dpt-cfg-master" )      ← 刻意不含 CRC
     *   salt   = SHA256(certDER)
     *   info   = "dpt-cfg-v1" + pkg
     *   out    = HKDF-SHA256(master, salt, info, 48)
     *
     * ⚠️ 为什么配置链的 master **不能**混入 CRC32(.text)（与段密钥不同）：
     *   配置只有一份（assets/xixin_config），而 4 个 ABI 的 so 各有不同的
     *   .text CRC（实测 arm=0xf38fa79d / arm64=0xbbb30a8d / x86=0x359a023e /
     *   x86_64=0xe50120a1）。运行期在哪个 ABI 上跑就算出哪个 CRC，
     *   若 master 掺了它，同一份配置在不同 ABI 上必然解不开。
     *   段密钥没这个问题：每个 ABI 的 so 各自加密自己的 .bitcode。
     *
     * 代价（如实记录）：配置链失去"改 .text 即自毁"的自绑定特性。
     * 它仍绑定 seed + 证书 + 包名，且产物里不再有任何密钥材料 ——
     * 相比旧方案（key 明文躺在导出符号里）仍是数量级的提升。
     */
    private byte[] deriveConfigMaterial() {
        String seed = readKeyladderSeed();
        String pkg = getPackageName();
        if (pkg == null || pkg.isEmpty()) {
            throw new IllegalStateException("配置派生：包名为空");
        }
        byte[] certDer;
        try {
            certDer = com.luoye.dpt.util.KeyLadder.extractFirstCertDer(getCertSourceFile());
        } catch (Exception e) {
            throw new IllegalStateException("配置派生：提取证书失败", e);
        }
        if (certDer == null) {
            throw new IllegalStateException("配置派生：无法从 APK 提取证书 DER: "
                    + getCertSourceFile().getAbsolutePath());
        }
        long seedVal = Long.parseUnsignedLong(seed, 16);
        return com.luoye.dpt.util.KeyLadder.deriveConfigMaterial(seedVal, certDer, pkg);
    }

    /**
     * Write proxy ApplicationName
     */
    public abstract void writeProxyAppName(String manifestDir);

    public abstract void writeProxyComponentFactoryName(String manifestDir);

    public abstract void setExtractNativeLibs(String manifestDir);

    public abstract void setDebuggable(String manifestDir,boolean debuggable);

    public File getWorkspaceDir() {
        return FileUtils.getDir(Const.ROOT_OF_OUT_DIR, "dptOut-" + Const.RANDOM_DIR_NAME);
    }

    /**
     * Get last process（zipalign，sign）dir
     */
    public File getLastProcessDir() {
        return FileUtils.getDir(Const.ROOT_OF_OUT_DIR, "dptLastProcess-" + Const.RANDOM_DIR_NAME);
    }

    protected abstract File getOutAssetsDir(String packageDir);

    public abstract String getLibDir(String packageDir);

    public abstract String getDexDir(String packageDir);

    public File getKeepDexTempDir(String packageDir) {
        return FileUtils.getDir(getDexDir(packageDir), "keep-dex-dir");
    }

    public String getProxyApplicationName() {
        return String.format(Locale.US, "%s.%s", ShellConfig.getInstance().getShellPackageName(), "ProxyApplication");
    }

    public String getProxyComponentFactory() {
        return String.format(Locale.US, "%s.%s", ShellConfig.getInstance().getShellPackageName(), "ProxyComponentFactory");
    }

    protected String getProxyDexPath() {
        return FileUtils.getExecutablePath() + File.separator + "shell-files" + File.separator + "dex" + File.separator + "classes.dex";
    }

    protected String getRenameDexPath() {
        return FileUtils.getExecutablePath() + File.separator + "shell-files" + File.separator + "dex" + File.separator + "rename_classes.dex";
    }

    private void addProxyDex(String packageOutDir) {
        addDex(getProxyDexPath(), packageOutDir);
    }

    protected String getJunkCodeDexPath() {
        return FileUtils.getExecutablePath() + File.separator + "shell-files" + File.separator + "dex" + File.separator + "junkcode.dex";
    }

    protected void addJunkCodeDex(String packageDir) {
        String dexDir = getDexDir(packageDir);
        File mainDex = new File(dexDir, "classes.dex");
        File junkCodeDex = new File(getJunkCodeDexPath());
        if(mainDex.exists() && DexUtils.mergeDex(mainDex, junkCodeDex)) {
            LogUtils.info("Merge junk code into classes.dex");
        }
        else {
            addDex(getJunkCodeDexPath(), dexDir);
        }
    }

    /* ── 把外部 dex 合并进壳 dex（--extra-dex）──────────────────────────
     *
     * 返回【合并后应当被读取的那个文件】：
     *   · 没配 --extra-dex  → 原样返回传入的 file（零行为变更）
     *   · 配了              → 返回 WORK 下的临时副本（不改 shell-files 共享文件）
     *
     * 为什么不能原地改传入文件：
     *   shell-files/dex/classes.dex 是 dpt.jar 分发的共享资产，所有打包共用。
     *   原地写会让第二次打包把上一包的桩带进去（跨包污染），且只读介质会失败。
     *
     * 失败策略：不静默降级——桩没进壳 dex 就等于联动失效，
     *   宁可打包失败也不要产出"以为防了其实没防"的包。
     */
    protected File mergeExtraDexIntoTempCopy(File shellDex) {
        if (extraDexPath == null || extraDexPath.isEmpty()) {
            return shellDex;
        }
        File extraDex = new File(extraDexPath);
        if (!extraDex.isFile()) {
            throw new IllegalStateException("--extra-dex 文件不存在: " + extraDexPath);
        }
        if (!shellDex.isFile()) {
            throw new IllegalStateException("--extra-dex：壳 dex 不存在: " + shellDex);
        }
        File tmp;
        try {
            tmp = File.createTempFile("dpt-shelldex-", ".dex");
        } catch (IOException e) {
            throw new IllegalStateException("--extra-dex：创建临时文件失败", e);
        }
        try {
            IoUtils.copyFile(shellDex.getAbsolutePath(), tmp.getAbsolutePath());
        } catch (Exception e) {
            tmp.delete();
            throw new IllegalStateException("--extra-dex：复制壳 dex 失败", e);
        }
        if (!DexUtils.mergeDex(tmp, extraDex)) {
            tmp.delete();
            throw new IllegalStateException(
                    "--extra-dex 合并失败（DexMerger 拒绝，详见上一层日志）: " + extraDexPath);
        }
        LogUtils.info("Merged extra dex into shell dex: %s (%d bytes)",
                extraDexPath, tmp.length());
        return tmp;
    }

    public String getExtraDexPath() {
        return extraDexPath;
    }

    public String getStubSeed() {
        return stubSeed;
    }

    public void setStubSeed(String stubSeed) {
        this.stubSeed = stubSeed;
    }

    public void setCertSourcePath(String certSourcePath) {
        this.certSourcePath = certSourcePath;
    }

    /** 段加密派生链要读证书的那个 APK：优先 --cert-source，否则用 -f 输入。 */
    private File getCertSourceFile() {
        if (certSourcePath != null && !certSourcePath.isEmpty()) {
            return new File(certSourcePath);
        }
        return new File(getFilePath());
    }

    public void setExtraDexPath(String extraDexPath) {
        this.extraDexPath = extraDexPath;
    }

    protected void addKeepDexes(String packageDir) {        File keepDexTempDir = getKeepDexTempDir(packageDir);
        File[] files = keepDexTempDir.listFiles();

        if(files != null) {
            for (File file : files) {
                if(file.getName().endsWith(".dex")) {
                    addDex(file.getAbsolutePath(), getDexDir(packageDir));
                }
            }
        }
    }

    public void compressDexFiles(String packageDir) {
        Map<String, CompressionMethod> rulesMap = new HashMap<>();
        rulesMap.put("classes\\d*.dex", CompressionMethod.STORE);
        String unalignedFilePath = getOutAssetsDir(packageDir).getAbsolutePath() + File.separator + Const.KEY_DEXES_STORE_UNALIGNED_NAME;
        String alignedFilePath = getOutAssetsDir(packageDir).getAbsolutePath() + File.separator + Const.KEY_DEXES_STORE_NAME;
        ZipUtils.compress(getDexFiles(getDexDir(packageDir))
                , unalignedFilePath
                , rulesMap
        );
        RandomAccessFile randomAccessFile = null;
        FileOutputStream out = null;
        boolean isAligned = false;
        try {
            randomAccessFile = new RandomAccessFile(unalignedFilePath, "r");
            out = new FileOutputStream(alignedFilePath);
            ZipAlign.alignZip(randomAccessFile, out);
            IoUtils.close(randomAccessFile);
            IoUtils.close(out);
            org.apache.commons.io.FileUtils.forceDelete(new File(unalignedFilePath));
            LogUtils.info("zip aligned: " + alignedFilePath);
            isAligned = true;
        }
        catch (Exception e) {
            LogUtils.warn("WARNING: ZipAlign failed: %s", unalignedFilePath);
        }
        finally {
            IoUtils.close(randomAccessFile);
            IoUtils.close(out);
        }

        if(!isAligned) {
            try {
                Files.move(Paths.get(unalignedFilePath), Paths.get(alignedFilePath), StandardCopyOption.REPLACE_EXISTING);
            }
            catch (Exception e1) {
                e1.printStackTrace();
            }
        }
    }

    public void copyNativeLibs(String packageDir) {
        File sourceDirRoot = new File(FileUtils.getExecutablePath(), "shell-files" + File.separator + "libs");
        File destDirRoot = new File(getOutAssetsDir(packageDir).getAbsolutePath(), Const.KEY_LIBS_DIR_NAME);

        if (!destDirRoot.exists()) {
            destDirRoot.mkdirs();
        }

        File[] abiDirs = sourceDirRoot.listFiles();
        if (abiDirs == null) {
            return;
        }

        for (File abiDir : abiDirs) {
            if (!abiDir.isDirectory()) {
                continue;
            }

            String abiName = abiDir.getName();

            if (excludedAbi != null && excludedAbi.contains(abiName)) {
                LogUtils.info("Skipping excluded ABI: " + abiName);
                continue;
            }

            File destAbiDir = new File(destDirRoot, abiName);
            if (!destAbiDir.exists()) {
                destAbiDir.mkdirs();
            }

            File[] libFiles = abiDir.listFiles();
            if (libFiles == null) {
                continue;
            }

            for (File libFile : libFiles) {
                if (libFile.isFile() && libFile.getName().endsWith(".so")) {
                    File destFile = new File(destAbiDir, libFile.getName());
                    try {
                        Files.copy(libFile.toPath(), destFile.toPath(),
                                StandardCopyOption.REPLACE_EXISTING);
                    } catch (IOException e) {
                        LogUtils.error("Failed to copy library: " + e.getMessage());
                    }
                }
            }
        }
    }

    public void encryptSoFiles(String packageOutDir, byte[] rc4Key){
        // rc4Key 不再使用：.bitcode 走证书派生链，配置也走派生链，
        // 产物里不再落任何密钥材料。保留参数仅为 Apk/Aab 两个调用点的签名兼容。
        File obfDir = new File(getOutAssetsDir(packageOutDir).getAbsolutePath() + File.separator, Const.KEY_LIBS_DIR_NAME);
        File[] soAbiDirs = obfDir.listFiles();
        if(soAbiDirs == null) {
            return;
        }

        /* ── 派生材料：证书 + 包名 + seed（缺一即 fail-fast）────────────
         *
         * 原实现用 rc4Key 加密 .bitcode 后，把 key 明文写进 so 的
         * DPT_UNKNOWN_DATA 符号 —— readelf 找到符号 + dd 读出 16 字节，
         * 整条加密形同虚设。
         *
         * 现在 key 由派生链算出、不落盘：
         *   key    = HKDF(master, SHA256(certDER), "dpt-sec-v1"+pkg)
         *   master = SHA256(DPT_KL_SEED || CRC32(.text) || "dpt-kl-v1")
         *   · certDER 从【已签名 APK】提（运行期设备上读的是同一个证书）。
         *           默认取 -f 输入；若输入是未签名中间包（apk-protect-action
         *           流水线契约：产出未签名、开发者重签），必须用
         *           --cert-source 指向上传时的原始已签名 APK —— 那张证书
         *           与 sigcheck 的指纹同源，也与重签用的一致。
         *   · seed    从 shell-files/keyladder-seed.txt 读。它由 root
         *              build.gradle 生成并持久化，shell/build.gradle 用
         *              -DDPT_KL_SEED 传给 4 个 ABI —— 打包侧与运行期
         *              C 侧同一把 seed，不会 per-ABI 漂移。
         *   · CRC32   由 SoSectionLocker 现算（链接后即固定；AGP 的
         *              strip 只删 .symtab 不动 .text —— 已实测验证），
         *              C 侧 dpt_keyladder.c 用同一段 .text 文件字节算。
         *
         * 两侧一致性由 KeyLadderTest 的 9 项断言锁定。 */
        String seed = readKeyladderSeed();
        String pkg = getPackageName();
        File certApk = getCertSourceFile();
        byte[] certDer = null;
        try {
            certDer = com.luoye.dpt.util.KeyLadder.extractFirstCertDer(certApk);
        } catch (Exception e) {
            LogUtils.error("派生链：从 APK 提证书失败(%s): %s", certApk, e.getMessage());
        }
        if (certDer == null) {
            throw new IllegalStateException(
                    "派生链：无法从 APK 提取证书 DER: " + certApk.getAbsolutePath()
                    + "\n  若输入包未签名（流水线契约是产出未签名包），请用"
                    + " --cert-source 指向【已用目标 keystore 签名】的原始 APK。");
        }
        if (pkg == null || pkg.isEmpty()) {
            throw new IllegalStateException("派生链：包名为空");
        }

        for (File soAbiDir : soAbiDirs) {
            File[] soFiles = soAbiDir.listFiles();
            if (soFiles == null) {
                continue;
            }

            for (File soFile : soFiles) {
                if(!soFile.getAbsolutePath().endsWith(".so")) {
                    continue;
                }
                // 返回 false = 无 .bitcode 段（老版本 so），属正常不 fail。
                // IOException 就地转 IllegalStateException：锁箱失败
                // 必须 fail-fast，不能让 so 以明文/半加密状态进包。
                boolean locked;
                try {
                    locked = com.luoye.dpt.util.SoSectionLocker.lockBitcode(
                            soFile, seed, certDer, pkg);
                } catch (java.io.IOException e) {
                    throw new IllegalStateException(
                            "派生链：锁箱 " + soFile.getName() + " 失败", e);
                }
                // 不再调用 writeSoFileCryptKey()：DPT_UNKNOWN_DATA 已删除。
                //
                // 历史教训（两步都踩过，别再重演）：
                //   · v1.2.3 删掉写入 → 配置解密链断裂 → 真机 java_class == null
                //     abort（当时配置还依赖该符号）
                //   · v1.2.9 恢复写入 → 真机能启动，但逆向者 readelf + dd
                //     就能拿到 encKey，进而解出 stub_seed
                // 正确解法不是"写不写"，而是【让配置链不再依赖任何落盘的 key】——
                // 见 writeConfig() / deriveConfigMaterial()：配置材料改由
                // 证书派生链现算，产物里不留任何密钥材料。
                if (locked) {
                    LogUtils.info("派生链加密完成: %s", soFile.getName());
                }
            }
        }

    }

    /**
     * 读 shell-files/keyladder-seed.txt（16 位 hex，缺则 fail-fast）。
     * 来源：root build.gradle 生成，shell/build.gradle 的 afterAssembleCopy
     * 落盘，与 C 侧编译宏 DPT_KL_SEED 同源。
     */
    private String readKeyladderSeed() {
        File seedFile = new File(FileUtils.getExecutablePath(),
                "shell-files" + File.separator + "keyladder-seed.txt");
        if (!seedFile.isFile()) {
            throw new IllegalStateException(
                    "派生链：找不到 keyladder-seed.txt（" + seedFile.getAbsolutePath() + "）。"
                    + "CMake configure 会生成它；缺失说明 shell-files 与 dpt.jar 不同版本。");
        }
        try {
            byte[] b = java.nio.file.Files.readAllBytes(seedFile.toPath());
            String s = new String(b, java.nio.charset.StandardCharsets.UTF_8).trim();
            if (!s.matches("[0-9a-fA-F]{16}")) {
                throw new IllegalStateException("派生链：keyladder-seed.txt 内容非法: " + s);
            }
            return s.toLowerCase(java.util.Locale.US);
        } catch (java.io.IOException e) {
            throw new IllegalStateException("派生链：读 keyladder-seed.txt 失败", e);
        }
    }

    private void encryptSoFile(File soFile, byte[] rc4Key) {
        try (ReadElf readElf = new ReadElf(soFile)) {
            List<ReadElf.SectionHeader> sectionHeaders = readElf.getSectionHeaders();
            for (ReadElf.SectionHeader sectionHeader : sectionHeaders) {
                if(".bitcode".equals(sectionHeader.getName())) {
                    LogUtils.info("start encrypt %s section: %s, offset: %s, size: %s",
                            soFile.getAbsolutePath(),
                            sectionHeader.getName(),
                            HexUtils.toHexString(sectionHeader.getOffset()),
                            sectionHeader.getSize()
                    );

                    byte[] bitcode = IoUtils.readFile(soFile.getAbsolutePath(),
                            sectionHeader.getOffset(),
                            (int)sectionHeader.getSize()
                    );

                    byte[] enc = CryptoUtils.rc4Crypt(rc4Key, bitcode);
                    IoUtils.writeFile(soFile.getAbsolutePath(),enc,sectionHeader.getOffset());
                }
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void deleteAllDexFiles(String packageDir){
        List<File> dexFiles = getDexFiles(getDexDir(packageDir));
        for (File dexFile : dexFiles) {
            dexFile.delete();
        }
    }

    private void addDex(String dexFilePath, String dexFilesSavePath){
        File dexFile = new File(dexFilePath);
        List<File> dexFiles = getDexFiles(dexFilesSavePath);
        int newDexNameNumber = dexFiles.size() + 1;
        String newDexPath = dexFilesSavePath + File.separator + "classes.dex";
        if(newDexNameNumber > 1) {
            newDexPath = dexFilesSavePath + File.separator + String.format(Locale.US, "classes%d.dex", newDexNameNumber);
        }
        byte[] dexData = IoUtils.readFile(dexFile.getAbsolutePath());
        IoUtils.writeFile(newDexPath,dexData);
    }

    protected abstract String getManifestFilePath(String packageOutDir);

    public abstract void saveApplicationName(String packageOutDir);

    public abstract void saveAppComponentFactory(String packageOutDir);

    private boolean isSystemComponentFactory(String name){
        if(name.equals("androidx.core.app.CoreComponentFactory") || name.equals("android.support.v4.app.CoreComponentFactory")){
            return true;
        }
        return false;
    }

    public boolean isAndroidPackageFile(File f) {
        return f.getAbsolutePath().endsWith(".apk")
                || f.getAbsolutePath().endsWith(".aab");
    }

    public void extractDexCode(String packageDir, String dexCodeSavePath, byte[] soKey) {
        List<File> dexFiles = getDexFiles(getDexDir(packageDir));
        Map<Integer,List<Instruction>> instructionMap = new HashMap<>();
        String appNameNew = Const.KEY_CODE_ITEM_STORE_NAME;
        String dataOutputPath = dexCodeSavePath + File.separator + appNameNew;

        CountDownLatch countDownLatch = new CountDownLatch(dexFiles.size());
        AtomicInteger totalClassesCount = new AtomicInteger(0);
        AtomicInteger keepClassesCount = new AtomicInteger(0);

        ShellConfig shellConfig = ShellConfig.getInstance();
        shellConfig.setInsnsCryptKey(deriveConfigAesKey(soKey));
        for(File dexFile : dexFiles) {
            ThreadPool.getInstance().execute(() -> {
                final int dexNo = DexUtils.getDexNumber(dexFile.getName());
                if(dexNo < 0) {
                    countDownLatch.countDown();
                    return;
                }

                File injectedDexFile = new File(dexFile.getAbsolutePath() + "_inject.dex");

                try {
                    DexUtils.injectInvokeMethod(dexFile.getAbsolutePath(),
                            injectedDexFile.getAbsolutePath(),
                            shellConfig.getJniClassNameSig()
                    );

                    dexFile.delete();

                    injectedDexFile.renameTo(dexFile);
                }
                catch (Exception e) {
                    injectedDexFile.delete();
                }

                if(isKeepClasses() && DexUtils.dexContainsKeepInPlace(dexFile)) {
                    // Skip split entirely for dexes containing keep-in-place classes (e.g. Compose):
                    // the re-partition would break Compose's cross-dex interface linking and cause IncompatibleClassChangeError.
                    // The dex still goes through extractAllMethods (rule-matched classes are skipped as usual); it is just not split.
                    LogUtils.info("Skip split for dex with keep-in-place classes (e.g. Compose): %s", dexFile.getName());
                }
                else if(isKeepClasses()) {
                    File keepDex = new File(getKeepDexTempDir(packageDir).getAbsolutePath() + File.separator + dexFile.getName());
                    File splitDex = new File(dexFile.getAbsolutePath() + "_split.dex");

                    try {
                        Pair<Integer, Integer> classesCountPair = DexUtils.splitDex(dexFile, keepDex, splitDex);

                        keepClassesCount.set(keepClassesCount.get() + classesCountPair.getKey());
                        totalClassesCount.set(totalClassesCount.get() + classesCountPair.getValue());

                        dexFile.delete();

                        splitDex.renameTo(dexFile);
                    } catch (Exception e) {
                        LogUtils.warn("WARNING: split %s fail", dexFile.getName());
                        keepDex.delete();
                        splitDex.delete();
                    }
                }

                String extractedDexName = dexFile.getName().endsWith(".dex") ? dexFile.getName().replaceAll("\\.dex$", "_extracted.dat") : "_extracted.dat";
                File extractedDexFile = new File(dexFile.getParent(), extractedDexName);

                boolean obfuscate = !isSmaller();
                List<Instruction> ret = DexUtils.extractAllMethods(dexFile, extractedDexFile, getPackageName(), isDumpCode(), obfuscate);
                instructionMap.put(dexNo, ret);

                File dexFileRightHashes = new File(dexFile.getParent(), FileUtils.getNewFileSuffix(dexFile.getName(),"dat"));

                try {
                    DexUtils.writeHashes(extractedDexFile, dexFileRightHashes);
                    dexFile.delete();
                    dexFileRightHashes.renameTo(dexFile);
                }
                catch (Exception e) {
                }
                finally {
                    if(extractedDexFile.exists()) {
                        extractedDexFile.delete();
                    }
                }

                if("classes.dex".equals(dexFile.getName())) {
                    String dexSignature = DexUtils.getDexSignature(dexFile);
                    ShellConfig.getInstance().setDexSign(dexSignature);
                }
                countDownLatch.countDown();
            });

        }

        ThreadPool.getInstance().shutdown();

        try {
            countDownLatch.await();
        }
        catch (Exception ignored){
        }

        if(isKeepClasses()) {
            LogUtils.info("Keep classes: %d, total classes: %d", keepClassesCount.get(), totalClassesCount.get());
        }
        MultiDexCode multiDexCode = MultiDexCodeUtils.makeMultiDexCode(instructionMap);

        MultiDexCodeUtils.writeMultiDexCode(dataOutputPath,multiDexCode);

    }
    /**
     * Get all dex files
     */
    public List<File> getDexFiles(String dir) {
        List<File> dexFiles = new ArrayList<>();
        File dirFile = new File(dir);
        File[] files = dirFile.listFiles();
        if(files != null) {
            Arrays.stream(files).filter(it -> it.getName().endsWith(".dex")).forEach(dexFiles::add);
        }
        return dexFiles;
    }

    protected void buildPackage(String originPackagePath, String unpackFilePath, String savePath) {
        String outputPath = getOutputPath();
        File outputPathFile;
        String outputDir;
        String resultFileName = null;
        ShellConfig shellConfig = ShellConfig.getInstance();

        if (outputPath != null) {
            outputPathFile = new File(outputPath);
            if (isAndroidPackageFile(outputPathFile)) {
                outputPathFile = new File(outputPath.contains(File.separator) ? outputPath : "." + File.separator + outputPath);

                outputDir = outputPathFile.getParent();
                resultFileName = outputPathFile.getName();
            } else {
                outputDir = outputPath;
            }
        } else {
            outputDir = savePath;
        }

        File outputDirFile = new File(outputDir);
        if (!outputDirFile.exists()) {
            outputDirFile.mkdirs();
        }

        String originPackageName = new File(originPackagePath).getName();
        String packageLastProcessDir = getLastProcessDir().getAbsolutePath();

        String unzipalignPackagePath = outputDir
                + File.separator
                + (resultFileName != null ? "temp_" + resultFileName : getUnzipalignPackageName(originPackageName));

        if(isSmaller()) {
            LogUtils.info("Used smaller option");
        }
        ZipUtils.zip(unpackFilePath, unzipalignPackagePath, isSmaller());

        String keyStoreFilePath = packageLastProcessDir + File.separator + Const.KEY_STORE_ASSET_NAME;

        try {
            ZipUtils.readResourceFromRuntime(Const.KEY_STORE_ASSET_PATH, keyStoreFilePath);
        }
        catch (IOException e){
            e.printStackTrace();
        }

        String unsignedPackagePath = outputDir
                + File.separator
                + (resultFileName != null ? "unsigned_" + resultFileName : getUnsignPackageName(originPackageName));

        boolean zipalignSuccess = false;

        try {
            zipalign(unzipalignPackagePath, unsignedPackagePath);
            zipalignSuccess = true;
            LogUtils.info("zipalign success.");
        } catch (Exception e) {
            LogUtils.error("zipalign failed!");
        }

        String willSignPackagePath = zipalignSuccess ? unsignedPackagePath : unzipalignPackagePath;

        boolean signResult = false;

        String signedPackagePath = outputDir
                + File.separator
                + (resultFileName != null ? resultFileName : getSignedPackageName(originPackageName));

        if(isSign()) {
            if(shellConfig.getSignatureConfig() == null || !new File(shellConfig.getSignatureConfig().getKeystore()).exists()) {
                LogUtils.info("Use default key store");
                signResult = signPackageDebug(willSignPackagePath, keyStoreFilePath, signedPackagePath);
            }
            else {
                LogUtils.info("Use custom key store");
                signResult = sign(willSignPackagePath,
                        shellConfig.getSignatureConfig().getKeystore(),
                        signedPackagePath,
                        shellConfig.getSignatureConfig().getAlias(),
                        shellConfig.getSignatureConfig().getStorePassword(),
                        shellConfig.getSignatureConfig().getKeyPassword()
                        );
            }
        }
        else {
            try {
                if(outputPath != null) {
                    Files.copy(Paths.get(willSignPackagePath), Paths.get(signedPackagePath),
                            StandardCopyOption.REPLACE_EXISTING);
                }
            } catch (IOException ignored) {}
        }

        File willSignPackageFile = new File(willSignPackagePath);
        File signedPackageFile = new File(signedPackagePath);
        File keyStoreFile = new File(keyStoreFilePath);
        File idsigFile = new File(signedPackagePath + ".idsig");

        LogUtils.info("unsign package file: %s, exists: %s", willSignPackageFile.getAbsolutePath(), willSignPackageFile.exists());

        String resultPath = signedPackageFile.exists() ? signedPackageFile.getAbsolutePath() : willSignPackageFile.getAbsolutePath();

        if (signResult && willSignPackageFile.exists()) {
            willSignPackageFile.delete();
        }

        if(signResult) {
            LogUtils.info("signed package file: " + signedPackageFile.getAbsolutePath());
        }

        if(zipalignSuccess) {
            try {
                Files.deleteIfExists(Paths.get(unzipalignPackagePath));
            }catch (Exception e){
                LogUtils.debug("unzipalign package path err = %s", e);
            }
        }

        if (idsigFile.exists()) {
            idsigFile.delete();
        }

        if (keyStoreFile.exists()) {
            keyStoreFile.delete();
        }
        LogUtils.info("protected package output path: " + resultPath + "\n");
    }

    private boolean signPackageDebug(String packagePath, String keyStorePath, String signedPackagePath) {
        return sign(packagePath, keyStorePath, signedPackagePath,
                Const.KEY_ALIAS,
                Const.STORE_PASSWORD,
                Const.KEY_PASSWORD);
    }

    protected abstract boolean sign(String packagePath, String keyStorePath, String signedPackagePath,
                                String keyAlias,
                                String storePassword,
                                String KeyPassword);

    private static void zipalign(String inputPackagePath, String outputPackagePath) throws Exception{
        try (RandomAccessFile in = new RandomAccessFile(inputPackagePath, "r");
             FileOutputStream out = new FileOutputStream(outputPackagePath)) {
            ZipAlign.alignZip(in, out);
        }
    }

    private void processRuleFile() {
        try {
            if(!org.apache.commons.lang3.StringUtils.isBlank(getRulesFilePath())) {
                File file = new File(getRulesFilePath());
                LogUtils.debug("Exclude rules file: %s", file);
                List<String> strings = com.google.common.io.Files.readLines(file, StandardCharsets.UTF_8);
                ProtectRules protectRules = ProtectRules.getInstance();
                if (!strings.isEmpty()) {
                    protectRules.setExcludeRules(strings.toArray(String[]::new));
                } else {
                    LogUtils.debug("Exclude rules file is empty", file);

                }
            }
        }
        catch (IOException e) {
            LogUtils.info("Exclude rules file is unavailable: %s", e.getMessage());
        }
    }

    private void processProtectConfigFile() {
        // Default shell package uses placeholder "<random>", resolved later to "{appPackage}.shell"
        String autoShellPackageName = Const.SHELL_PACKAGE_NAME_AUTO;
        if(org.apache.commons.lang3.StringUtils.isBlank(getProtectConfigFile())) {
            ShellConfig.getInstance().init(autoShellPackageName);
            return;
        }

        try {
            LogUtils.info("Read config file: %s", getProtectConfigFile());
            byte[] bytes = IoUtils.readFile(getProtectConfigFile());
            String configData = new String(bytes, StandardCharsets.UTF_8);
            ShellConfig shellConfigFromFile = JSON.parseObject(configData, ShellConfig.class);

            if(shellConfigFromFile != null) {
                ShellConfig shellConfig = ShellConfig.getInstance();
                if(Const.SHELL_PACKAGE_NAME_AUTO.equals(shellConfigFromFile.getShellPackageName())) {
                    shellConfigFromFile.setShellPackageName(autoShellPackageName);
                }

                LogUtils.info("Use config: %s", shellConfigFromFile);
                shellConfig.init(shellConfigFromFile);

            }
            else {
                ShellConfig.getInstance().init(autoShellPackageName);
            }

        } catch (Exception e) {
            LogUtils.error("Read config file error");
            ShellConfig.getInstance().init(autoShellPackageName);
        }
    }

    /**
     * Resolve auto shell package name to "{applicationPackage}.shell" after package name is known.
     */
    public void resolveDefaultShellPackageName() {
        ShellConfig shellConfig = ShellConfig.getInstance();
        if (!Const.SHELL_PACKAGE_NAME_AUTO.equals(shellConfig.getShellPackageName())) {
            return;
        }

        String packageName = getPackageName();
        if (org.apache.commons.lang3.StringUtils.isBlank(packageName)) {
            String fallback = StringUtils.generateIdentifier(10);
            shellConfig.setShellPackageName(fallback);
            LogUtils.warn("Package name is empty, fallback to random shell package name: %s", fallback);
            return;
        }

        String shellPackageName = packageName + ".shell";
        shellConfig.setShellPackageName(shellPackageName);
        LogUtils.info("Shell package name: %s", shellPackageName);
    }

    private KeyStore loadKeyStore(InputStream inputStream, char[] password) {
        byte[] data;
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = inputStream.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
            data = baos.toByteArray();
        } catch (IOException e) {
            return null;
        }
        for (String type : new String[]{"JKS", "PKCS12", "BKS"}) {
            try {
                KeyStore ks = KeyStore.getInstance(type);
                ks.load(new ByteArrayInputStream(data), password);
                LogUtils.info("Loaded keystore as " + type);
                return ks;
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    private String computeSignatureSha256() {
        ShellConfig shellConfig = ShellConfig.getInstance();
        ShellConfig.SignatureConfig sigConfig = shellConfig.getSignatureConfig();

        String keystorePath = null;
        String storePassword = Const.STORE_PASSWORD;
        String alias = Const.KEY_ALIAS;

        if (sigConfig != null
                && !org.apache.commons.lang3.StringUtils.isBlank(sigConfig.getKeystore())
                && new File(sigConfig.getKeystore()).exists()) {
            keystorePath = sigConfig.getKeystore();
            if (!org.apache.commons.lang3.StringUtils.isBlank(sigConfig.getStorePassword())) {
                storePassword = sigConfig.getStorePassword();
            }
            if (!org.apache.commons.lang3.StringUtils.isBlank(sigConfig.getAlias())) {
                alias = sigConfig.getAlias();
            }
            LogUtils.info("Computing SHA-256 from signing keystore: " + keystorePath);
        } else {
            LogUtils.info("Computing SHA-256 from default keystore");
        }

        try {
            KeyStore ks = null;
            char[] pwdChars = storePassword.toCharArray();
            if (keystorePath != null) {
                try (FileInputStream fis = new FileInputStream(keystorePath)) {
                    ks = loadKeyStore(fis, pwdChars);
                }
            }

            if (ks == null) {
                LogUtils.error("Failed to load keystore");
                return null;
            }

            Certificate cert = ks.getCertificate(alias);
            if (cert == null) {
                LogUtils.error("Certificate not found for alias: " + alias);
                return null;
            }

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(cert.getEncoded());

            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format(Locale.US, "%02x", b));
            }
            return sb.toString();

        } catch (Exception e) {
            LogUtils.error("Failed to compute certificate SHA-256: " + e.getMessage());
            return null;
        }
    }

    public void protect() throws IOException {
        String path = "shell-files";
        File shellFiles = new File(FileUtils.getExecutablePath() + File.separator + path);
        if(!shellFiles.exists()) {
            String msg = "Cannot find directory: shell-files!" + shellFiles;
            LogUtils.error(msg);
            throw new FileNotFoundException(msg);
        }

        File willProtectFile = new File(getFilePath());

        if(!willProtectFile.exists()){
            String msg = String.format(Locale.US, "File not exists: %s", getFilePath());
            throw new FileNotFoundException(msg);
        }

        processRuleFile();
        processProtectConfigFile();

        ShellConfig shellConfig = ShellConfig.getInstance();
        // Merge CLI flags into config-file flags (each bit = one switch)
        shellConfig.setRiskCheckFlags(shellConfig.getRiskCheckFlags() | getRiskCheckFlags());
        // The CLI can only force in-memory dex on; the default is the on-disk
        // path, so there is nothing for the CLI to turn off.
        if (isUseInmemoryDex()) {
            shellConfig.setUseInmemoryDex(true);
        }

        if (isVerifySign()) {
            String sha256 = computeSignatureSha256();
            if (sha256 != null) {
                shellConfig.setAppSignSha256(sha256);
                LogUtils.info("Signature verification enabled, SHA-256: " + sha256);
            } else {
                LogUtils.error("Failed to compute certificate SHA-256, signature verification disabled.");
            }
        }

        /* --stub-seed：字符串桩的密钥流种子（packer 联动）。
         * 校验形态（16 位 hex）—— 非法值宁可不写也不要写进去：
         * 运行期 gseed() 返回 0 时桩会用 0 当种子解全部字符串，
         * 结果是静默乱码，比直接失败难查得多。 */
        if (getStubSeed() != null && !getStubSeed().isEmpty()) {
            String seed = getStubSeed().trim();
            if (!seed.matches("[0-9a-fA-F]{16}")) {
                throw new IllegalArgumentException(
                        "--stub-seed 必须是 16 位十六进制字符串，收到: " + seed);
            }
            shellConfig.setStubSeed(seed.toLowerCase(Locale.US));
            LogUtils.info("Stub seed (for stringenc link): " + seed);
        }

        JunkCodeGenerator.generateJunkCodeDex(new File(getJunkCodeDexPath()));
    }

}
