package com.luoyesiqiu.shell;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.text.TextUtils;
import android.util.Log;

import com.luoyesiqiu.shell.util.EnvUtils;
import com.luoyesiqiu.shell.util.FileUtils;

/**
 * Created by luoyesiqiu
 */
public class ProxyApplication extends Application {
    private static final String TAG = ProxyApplication.class.getSimpleName();
    private String realApplicationName = "";
    private Application realApplication = null;

    private void replaceApplication() {
        if (Global.sNeedCalledApplication && !TextUtils.isEmpty(realApplicationName)) {
            realApplication = (Application) JniBridge.ra(realApplicationName);
            Log.d(TAG, "applicationExchange: " + realApplicationName + ", realApplication: " + realApplication.getClass().getName());

            JniBridge.craoc(realApplicationName);
            Global.sNeedCalledApplication = false;
        }
    }
    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "dpt onCreate");
        replaceApplication();
    }
    @Override
    public Context createPackageContext(String packageName, int flags) throws PackageManager.NameNotFoundException {
        Log.d(TAG, "createPackageContext: " + realApplicationName);
        if(!TextUtils.isEmpty(realApplicationName)){
            replaceApplication();
            return realApplication;
        }
        return super.createPackageContext(packageName, flags);
    }

    @Override
    public String getPackageName() {
        if(!TextUtils.isEmpty(realApplicationName)){
            return "";
        }
        return super.getPackageName();
    }
    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        Log.d(TAG,"dpt attachBaseContext classloader = " + base.getClassLoader());
        if(!Global.sIsReplacedClassLoader) {
            ApplicationInfo applicationInfo = base.getApplicationInfo();
            if(applicationInfo == null) {
                throw new NullPointerException("application info is null");
            }
            FileUtils.unzipLibs(applicationInfo.sourceDir, applicationInfo.dataDir);
            JniBridge.loadShellLibs(applicationInfo.dataDir);
            Log.d(TAG,"ProxyApplication init");
            JniBridge.ia();
            ClassLoader targetClassLoader = base.getClassLoader();
            JniBridge.cbde(targetClassLoader);
            Global.sIsReplacedClassLoader = true;
        }

        realApplicationName = JniBridge.rapn();

        // 报错四十五（方案：apk-protect-action/docs/后台dexopt方案.md）：
        // 业务 dex 在装包期对 dex2oat 不可见（装包日志实证系统降级 verify），
        // 启动期现场校验约 1,660 类 + 解释执行（trace 实测 +227ms）。
        // 解密落盘之后，后台补一次 quicken 档 dexopt：第二次起冷启动跳过
        // 校验并命中快速化指令。全兜底失败静默，最坏回到现状。
        // 放在 attachBaseContext（三入口路径都经过；onCreate 在 ACF 路径会被跳过）。
        BackgroundDexopt.schedule(getCodeCacheDir().getAbsolutePath(),
                EnvUtils.getAbiDirName(), 5_000);
    }

}
