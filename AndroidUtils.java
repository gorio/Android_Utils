public class AndroidUtils {

  
  /**
   * Obtain all PreInstalled Apps
   * @return String
   */
  public static String getAllPreInstalledApplications() {
  
          String allPreInstalledApplications = "";
  
          PackageManager pm = getPackageManager();
          List<ApplicationInfo> installedApplications = pm
                  .getInstalledApplications(PackageManager.GET_META_DATA);
  
          for (ApplicationInfo applicationInfo : installedApplications) {
              if (isApplicationPreInstalled(applicationInfo)) {
                  allPreInstalledApplications += applicationInfo.processName + "\n";
              }
          }
  
          return allPreInstalledApplications;
  }
  
  /**
   * Verify if an App is a PreInstalled Apps
   * @param applicationInfo
   * @return boolean
   */
  public static boolean isApplicationPreInstalled(ApplicationInfo applicationInfo) {
      if (applicationInfo != null) {
          int allTheFlagsInHex = Integer.valueOf(
                  String.valueOf(applicationInfo.flags), 16);
          /*
           If flags is an uneven number, then it
           is a preinstalled application, because in that case
           ApplicationInfo.FLAG_SYSTEM ( == 0x00000001 )
           is added to flags
            */
          if ((allTheFlagsInHex % 2) != 0) {
              return true;
          }
      }
      return false;
  }
  
  /**
     * Verify if an App has update
     * @param package_name
     * @return boolean
     */
    private boolean needUpdate(String package_name) {
        boolean rc = false;
        try {
            String curVersion = this.getPackageManager().getPackageInfo(package_name, 0).versionName;
            String newVersion = curVersion;
            newVersion = Jsoup.connect("https://play.google.com/store/apps/details?id=" + package_name + "&hl=en")
                    .timeout(30000)
                    .userAgent("Mozilla/5.0 (Windows; U; WindowsNT 5.1; en-US; rv1.8.1.6) Gecko/20070725 Firefox/2.0.0.6")
                    .referrer("http://www.google.com")
                    .get()
                    .select("div[itemprop=softwareVersion]")
                    .first()
                    .ownText();
            rc = (curVersion.equals(newVersion)) ? false : true;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return rc;
    }

public boolean isRunning(Context ctx) {
        ActivityManager activityManager = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
        List<RunningTaskInfo> tasks = activityManager.getRunningTasks(Integer.MAX_VALUE);

        for (RunningTaskInfo task : tasks) {
            if (ctx.getPackageName().equalsIgnoreCase(task.baseActivity.getPackageName())) 
                return true;                                  
        }

        return false;
    }
    
    //Here's an example broadcast receiver:

public class SystemUpdateClass extends BroadcastReceiver{
   @Override
   public void onReceive(Context context, Intent intent){
      if (intent.getAction().equals("android.settings.SYSTEM_UPDATE_SETTINGS")){
           Toast.makeText(context, 
                 "Yup! Received a system update broadcast", 
                 Toast.LENGTH_SHORT).show();
      }
   }
}

//Here's an example code, from within a activity's onCreate:

SystemUpdateClass sysUpdate = new SystemUpdateClass();
IntentFilter filter = new IntentFilter();
filter.addAction("android.settings.SYSTEM_UPDATE_SETTINGS");
registerReceiver(sysUpdate, filter);
}
