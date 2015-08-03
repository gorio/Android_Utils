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

}
