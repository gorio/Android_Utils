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

Three points to improve the readability of the image: 1)Resize the image with variable height and width(multiply 0.5 and 1 and 2 with image height and width). 2)Convert the image to Gray scale format(Black and white). 3)Remove the noise pixels and make more clear(Filter the image).

//Resize
  public Bitmap Resize(Bitmap bmp, int newWidth, int newHeight)
        {

                Bitmap temp = (Bitmap)bmp;

                Bitmap bmap = new Bitmap(newWidth, newHeight, temp.PixelFormat);

                double nWidthFactor = (double)temp.Width / (double)newWidth;
                double nHeightFactor = (double)temp.Height / (double)newHeight;

                double fx, fy, nx, ny;
                int cx, cy, fr_x, fr_y;
                Color color1 = new Color();
                Color color2 = new Color();
                Color color3 = new Color();
                Color color4 = new Color();
                byte nRed, nGreen, nBlue;

                byte bp1, bp2;

                for (int x = 0; x < bmap.Width; ++x)
                {
                    for (int y = 0; y < bmap.Height; ++y)
                    {

                        fr_x = (int)Math.Floor(x * nWidthFactor);
                        fr_y = (int)Math.Floor(y * nHeightFactor);
                        cx = fr_x + 1;
                        if (cx >= temp.Width) cx = fr_x;
                        cy = fr_y + 1;
                        if (cy >= temp.Height) cy = fr_y;
                        fx = x * nWidthFactor - fr_x;
                        fy = y * nHeightFactor - fr_y;
                        nx = 1.0 - fx;
                        ny = 1.0 - fy;

                        color1 = temp.GetPixel(fr_x, fr_y);
                        color2 = temp.GetPixel(cx, fr_y);
                        color3 = temp.GetPixel(fr_x, cy);
                        color4 = temp.GetPixel(cx, cy);

                        // Blue
                        bp1 = (byte)(nx * color1.B + fx * color2.B);

                        bp2 = (byte)(nx * color3.B + fx * color4.B);

                        nBlue = (byte)(ny * (double)(bp1) + fy * (double)(bp2));

                        // Green
                        bp1 = (byte)(nx * color1.G + fx * color2.G);

                        bp2 = (byte)(nx * color3.G + fx * color4.G);

                        nGreen = (byte)(ny * (double)(bp1) + fy * (double)(bp2));

                        // Red
                        bp1 = (byte)(nx * color1.R + fx * color2.R);

                        bp2 = (byte)(nx * color3.R + fx * color4.R);

                        nRed = (byte)(ny * (double)(bp1) + fy * (double)(bp2));

                        bmap.SetPixel(x, y, System.Drawing.Color.FromArgb
                (255, nRed, nGreen, nBlue));
                    }
                }



                bmap = SetGrayscale(bmap);
                bmap = RemoveNoise(bmap);

                return bmap;

        }


//SetGrayscale
  public Bitmap SetGrayscale(Bitmap img)
        {

            Bitmap temp = (Bitmap)img;
            Bitmap bmap = (Bitmap)temp.Clone();
            Color c;
            for (int i = 0; i < bmap.Width; i++)
            {
                for (int j = 0; j < bmap.Height; j++)
                {
                    c = bmap.GetPixel(i, j);
                    byte gray = (byte)(.299 * c.R + .587 * c.G + .114 * c.B);

                    bmap.SetPixel(i, j, Color.FromArgb(gray, gray, gray));
                }
            }
            return (Bitmap)bmap.Clone();

        }
//RemoveNoise
   public Bitmap RemoveNoise(Bitmap bmap)
        {

            for (var x = 0; x < bmap.Width; x++)
            {
                for (var y = 0; y < bmap.Height; y++)
                {
                    var pixel = bmap.GetPixel(x, y);
                    if (pixel.R < 162 && pixel.G < 162 && pixel.B < 162)
                        bmap.SetPixel(x, y, Color.Black);
                }
            }

            for (var x = 0; x < bmap.Width; x++)
            {
                for (var y = 0; y < bmap.Height; y++)
                {
                    var pixel = bmap.GetPixel(x, y);
                    if (pixel.R > 162 && pixel.G > 162 && pixel.B > 162)
                        bmap.SetPixel(x, y, Color.White);
                }
            }

            return bmap;
        }

}
