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

// EXCEL
// AndroidManifest.xml: <uses-permissionandroid:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
// Gradle: compile 'org.apache.poi:poi:3.9'

    /**
     * Save data to Excel file
     * @param context
     * @param fileName (i.e. myExcel.xls)
     * @return boolean
     */
    private static boolean saveExcelFile(Context context, String fileName) {

        // check if available and not read only
        if (!isExternalStorageAvailable() || isExternalStorageReadOnly()) {
            Log.e(TAG, "Storage not available or read only");
            return false;
        }

        boolean success = false;

        //New Workbook
        Workbook wb = new HSSFWorkbook();

        Cell c = null;

        //Cell style for header row
        CellStyle cs = wb.createCellStyle();
        cs.setFillForegroundColor(HSSFColor.LIME.index);
        cs.setFillPattern(HSSFCellStyle.SOLID_FOREGROUND);

        //New Sheet
        Sheet sheet1 = null;
        sheet1 = wb.createSheet("myOrder");

        // Generate column headings
        Row row = sheet1.createRow(0);
        Row row1 = sheet1.createRow(1);

        c = row.createCell(0);
        c.setCellValue("Item Number");
        c.setCellStyle(cs);

        c = row.createCell(1);
        c.setCellValue("Quantity");
        c.setCellStyle(cs);

        c = row.createCell(2);
        c.setCellValue("Price");
        c.setCellStyle(cs);

        c = row1.createCell(0);
        c.setCellValue("1");

        c = row1.createCell(1);
        c.setCellValue("10");

        c = row1.createCell(2);
        c.setCellValue("20,25");

        sheet1.setColumnWidth(0, (15 * 500));
        sheet1.setColumnWidth(1, (15 * 500));
        sheet1.setColumnWidth(2, (15 * 500));

        // Create a path where we will place our List of objects on external storage
        File file = new File(context.getExternalFilesDir(null), fileName);
        FileOutputStream os = null;

        try {
            os = new FileOutputStream(file);
            wb.write(os);
            Log.w("FileUtils", "Writing file" + file);
            success = true;
        } catch (IOException e) {
            Log.w("FileUtils", "Error writing " + file, e);
        } catch (Exception e) {
            Log.w("FileUtils", "Failed to save file", e);
        } finally {
            try {
                if (null != os)
                    os.close();
            } catch (Exception ex) {
            }
        }
        return success;
    }

    /**
     * Save data to Excel file
     * @param context
     * @param fileName (i.e. myExcel.xls)
     */
    private static void readExcelFile(Context context, String fileName) {

        if (!isExternalStorageAvailable() || isExternalStorageReadOnly())
        {
            Log.e(TAG, "Storage not available or read only");
            return;
        }

        try{
            // Creating Input Stream
            File file = new File(context.getExternalFilesDir(null), fileName);
            FileInputStream myInput = new FileInputStream(file);

            // Create a POIFSFileSystem object
            POIFSFileSystem myFileSystem = new POIFSFileSystem(myInput);

            // Create a workbook using the File System
            HSSFWorkbook myWorkBook = new HSSFWorkbook(myFileSystem);

            // Get the first sheet from workbook
            HSSFSheet mySheet = myWorkBook.getSheetAt(0);

            /** We now need something to iterate through the cells.**/
            Iterator rowIter = mySheet.rowIterator();

            while(rowIter.hasNext()){
                HSSFRow myRow = (HSSFRow) rowIter.next();
                Iterator cellIter = myRow.cellIterator();
                while(cellIter.hasNext()){
                    HSSFCell myCell = (HSSFCell) cellIter.next();
                    Log.d(TAG, "Cell Value: " +  myCell.toString());
                    Toast.makeText(context, "cell Value: " + myCell.toString(), Toast.LENGTH_SHORT).show();
                }
            }
        }catch (Exception e){e.printStackTrace(); }

        return;
    }

    /**
     * Check status of External Storage
     * @return boolean
     */
    public static boolean isExternalStorageReadOnly() {
        String extStorageState = Environment.getExternalStorageState();
        if (Environment.MEDIA_MOUNTED_READ_ONLY.equals(extStorageState)) {
            return true;
        }
        return false;
    }

    /**
     * Check if External Storage is Available
     * @return boolean
     */
    public static boolean isExternalStorageAvailable() {
        String extStorageState = Environment.getExternalStorageState();
        if (Environment.MEDIA_MOUNTED.equals(extStorageState)) {
            return true;
        }
        return false;
    }
    
    // Sending side
    byte[] data = text.getBytes("UTF-8");
    String base64 = Base64.encodeToString(data, Base64.DEFAULT);
    
    // Receiving side
    byte[] data = Base64.decode(base64, Base64.DEFAULT);
    String text = new String(data, "UTF-8");
}
