public class AndroidUtils {

   /**
     * Change Locale programmatically
     */
public void changeLanguage(String language, String country) {
        Locale locale = new Locale(language, country);
        Resources resources = getResources();
        DisplayMetrics displayMetrics = resources.getDisplayMetrics();
        Configuration configuration = resources.getConfiguration();
        configuration.locale = locale;
        resources.updateConfiguration(configuration, displayMetrics);
    }

  /**
     * Process Info
     */
    public static void processInfo() {

        ActivityManager activityManager = (ActivityManager) context.getSystemService(ACTIVITY_SERVICE);
        MemoryInfo memoryInfo = new ActivityManager.MemoryInfo();
        activityManager.getMemoryInfo(memoryInfo);

        Log.i(TAG, " memoryInfo.availMem " + memoryInfo.availMem + "\n");
        Log.i(TAG, " memoryInfo.lowMemory " + memoryInfo.lowMemory + "\n");
        Log.i(TAG, " memoryInfo.threshold " + memoryInfo.threshold + "\n");

        List<RunningAppProcessInfo> runningAppProcesses = activityManager.getRunningAppProcesses();

        Map<Integer, String> pidMap = new TreeMap<Integer, String>();
        for (RunningAppProcessInfo runningAppProcessInfo : runningAppProcesses) {
            pidMap.put(runningAppProcessInfo.pid, runningAppProcessInfo.processName);
        }

        Collection<Integer> keys = pidMap.keySet();

        for (int key : keys) {
            int pids[] = new int[1];
            pids[0] = key;
            android.os.Debug.MemoryInfo[] memoryInfoArray = activityManager.getProcessMemoryInfo(pids);
            for (android.os.Debug.MemoryInfo pidMemoryInfo : memoryInfoArray) {
                Log.i(TAG, String.format("** MEMINFO in pid %d [%s] **\n", pids[0], pidMap.get(pids[0])));
                Log.i(TAG, " pidMemoryInfo.getTotalPrivateDirty(): " + pidMemoryInfo.getTotalPrivateDirty() + "\n");
                Log.i(TAG, " pidMemoryInfo.getTotalPss(): " + pidMemoryInfo.getTotalPss() + "\n");
                Log.i(TAG, " pidMemoryInfo.getTotalSharedDirty(): " + pidMemoryInfo.getTotalSharedDirty() + "\n");
            }
        }
    }
  
  
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

// Bluetooth

private void pairDevice(BluetoothDevice device) {
try {
    if (D)
    Log.d(TAG, "Start Pairing...");

    waitingForBonding = true;

    Method m = device.getClass()
        .getMethod("createBond", (Class[]) null);
    m.invoke(device, (Object[]) null);

    if (D)
    Log.d(TAG, "Pairing finished.");
} catch (Exception e) {
    Log.e(TAG, e.getMessage());
}
}

private void unpairDevice(BluetoothDevice device) {
try {
    Method m = device.getClass()
        .getMethod("removeBond", (Class[]) null);
    m.invoke(device, (Object[]) null);
} catch (Exception e) {
    Log.e(TAG, e.getMessage());
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
    
    //Encryption encryption = Encryption.getDefault("Key", "Salt", new byte[16]);
    //String encrypted = encryption.encryptOrNull("top secret string");
    //String decrypted = encryption.decryptOrNull(encrypted);
    
    /**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package se.simbio.encryption;

import android.os.AsyncTask;
import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A class to make more easy and simple the encrypt routines, this is the core of Encryption library
 */
public class Encryption {

    /**
     * We use this tag to log errors on LogCat, never the password or sensible data
     */
    private static final String TAG = "Encryption";

    /**
     * The Builder used to create the Encryption instance and that contains the information about
     * encryption specifications, this instance need to be private and careful managed
     */
    private final Builder mBuilder;

    /**
     * The private and unique constructor, you should use the Encryption.Builder to build your own
     * instance or get the default proving just the sensible information about encryption
     */
    private Encryption(Builder builder) {
        mBuilder = builder;
    }

    /**
     * @return an default encryption instance or {@code null} if occur some Exception, you can
     * create yur own Encryption instance using the Encryption.Builder
     */
    public static Encryption getDefault(String key, String salt, byte[] iv) {
        try {
            return Builder.getDefaultBuilder(key, salt, iv).build();
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Encrypt a String
     *
     * @param data the String to be encrypted
     *
     * @return the encrypted String or {@code null} if you send the data as {@code null}
     *
     * @throws UnsupportedEncodingException       if the Builder charset name is not supported or if
     *                                            the Builder charset name is not supported
     * @throws NoSuchAlgorithmException           if the Builder digest algorithm is not available
     *                                            or if this has no installed provider that can
     *                                            provide the requested by the Builder secret key
     *                                            type or it is {@code null}, empty or in an invalid
     *                                            format
     * @throws NoSuchPaddingException             if no installed provider can provide the padding
     *                                            scheme in the Builder digest algorithm
     * @throws InvalidAlgorithmParameterException if the specified parameters are inappropriate for
     *                                            the cipher
     * @throws InvalidKeyException                if the specified key can not be used to initialize
     *                                            the cipher instance
     * @throws InvalidKeySpecException            if the specified key specification cannot be used
     *                                            to generate a secret key
     * @throws BadPaddingException                if the padding of the data does not match the
     *                                            padding scheme
     * @throws IllegalBlockSizeException          if the size of the resulting bytes is not a
     *                                            multiple of the cipher block size
     * @throws NullPointerException               if the Builder digest algorithm is {@code null} or
     *                                            if the specified Builder secret key type is
     *                                            {@code null}
     * @throws IllegalStateException              if the cipher instance is not initialized for
     *                                            encryption or decryption
     */
    public String encrypt(String data) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, BadPaddingException, IllegalBlockSizeException {
        if (data == null) return null;
        SecretKey secretKey = getSecretKey(hashTheKey(mBuilder.getKey()));
        byte[] dataBytes = data.getBytes(mBuilder.getCharsetName());
        Cipher cipher = Cipher.getInstance(mBuilder.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, mBuilder.getIvParameterSpec(), mBuilder.getSecureRandom());
        return Base64.encodeToString(cipher.doFinal(dataBytes), mBuilder.getBase64Mode());
    }

    /**
     * This is a sugar method that calls encrypt method and catch the exceptions returning
     * {@code null} when it occurs and logging the error
     *
     * @param data the String to be encrypted
     *
     * @return the encrypted String or {@code null} if you send the data as {@code null}
     */
    public String encryptOrNull(String data) {
        try {
            return encrypt(data);
        } catch (Exception e) {
            Log.e(TAG, e.getMessage(), e);
            return null;
        }
    }

    /**
     * This is a sugar method that calls encrypt method in background, it is a good idea to use this
     * one instead the default method because encryption can take several time and with this method
     * the process occurs in a AsyncTask, other advantage is the Callback with separated methods,
     * one for success and other for the exception
     *
     * @param data     the String to be encrypted
     * @param callback the Callback to handle the results
     */
    public void encryptAsync(String data, final Callback callback) {
        if (callback == null) return;
        new AsyncTask<String, Void, String>() {

            @Override
            protected String doInBackground(String... params) {
                try {
                    String encrypt = encrypt(params[0]);
                    if (encrypt == null) {
                        callback.onError(new Exception("Encrypt return null, it normally occurs when you send a null data"));
                    }
                    return encrypt;
                } catch (Exception e) {
                    callback.onError(e);
                    return null;
                }
            }

            @Override
            protected void onPostExecute(String result) {
                super.onPostExecute(result);
                if (result != null) callback.onSuccess(result);
            }

        }.execute(data);
    }

    /**
     * Decrypt a String
     *
     * @param data the String to be decrypted
     *
     * @return the decrypted String or {@code null} if you send the data as {@code null}
     *
     * @throws UnsupportedEncodingException       if the Builder charset name is not supported or if
     *                                            the Builder charset name is not supported
     * @throws NoSuchAlgorithmException           if the Builder digest algorithm is not available
     *                                            or if this has no installed provider that can
     *                                            provide the requested by the Builder secret key
     *                                            type or it is {@code null}, empty or in an invalid
     *                                            format
     * @throws NoSuchPaddingException             if no installed provider can provide the padding
     *                                            scheme in the Builder digest algorithm
     * @throws InvalidAlgorithmParameterException if the specified parameters are inappropriate for
     *                                            the cipher
     * @throws InvalidKeyException                if the specified key can not be used to initialize
     *                                            the cipher instance
     * @throws InvalidKeySpecException            if the specified key specification cannot be used
     *                                            to generate a secret key
     * @throws BadPaddingException                if the padding of the data does not match the
     *                                            padding scheme
     * @throws IllegalBlockSizeException          if the size of the resulting bytes is not a
     *                                            multiple of the cipher block size
     * @throws NullPointerException               if the Builder digest algorithm is {@code null} or
     *                                            if the specified Builder secret key type is
     *                                            {@code null}
     * @throws IllegalStateException              if the cipher instance is not initialized for
     *                                            encryption or decryption
     */
    public String decrypt(String data) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if (data == null) return null;
        byte[] dataBytes = Base64.decode(data, mBuilder.getBase64Mode());
        SecretKey secretKey = getSecretKey(hashTheKey(mBuilder.getKey()));
        Cipher cipher = Cipher.getInstance(mBuilder.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, mBuilder.getIvParameterSpec(), mBuilder.getSecureRandom());
        byte[] dataBytesDecrypted = (cipher.doFinal(dataBytes));
        return new String(dataBytesDecrypted);
    }

    /**
     * This is a sugar method that calls decrypt method and catch the exceptions returning
     * {@code null} when it occurs and logging the error
     *
     * @param data the String to be decrypted
     *
     * @return the decrypted String or {@code null} if you send the data as {@code null}
     */
    public String decryptOrNull(String data) {
        try {
            return decrypt(data);
        } catch (Exception e) {
            Log.e(TAG, e.getMessage(), e);
            return null;
        }
    }

    /**
     * This is a sugar method that calls decrypt method in background, it is a good idea to use this
     * one instead the default method because decryption can take several time and with this method
     * the process occurs in a AsyncTask, other advantage is the Callback with separated methods,
     * one for success and other for the exception
     *
     * @param data     the String to be decrypted
     * @param callback the Callback to handle the results
     */
    public void decryptAsync(String data, final Callback callback) {
        if (callback == null) return;
        new AsyncTask<String, Void, String>() {

            @Override
            protected String doInBackground(String... params) {
                try {
                    String decrypt = decrypt(params[0]);
                    if (decrypt == null) {
                        callback.onError(new Exception("Decrypt return null, it normally occurs when you send a null data"));
                    }
                    return decrypt;
                } catch (Exception e) {
                    callback.onError(e);
                    return null;
                }
            }

            @Override
            protected void onPostExecute(String result) {
                super.onPostExecute(result);
                if (result != null) callback.onSuccess(result);
            }

        }.execute(data);
    }

    /**
     * creates a 128bit salted aes key
     *
     * @param key encoded input key
     *
     * @return aes 128 bit salted key
     *
     * @throws NoSuchAlgorithmException     if no installed provider that can provide the requested
     *                                      by the Builder secret key type
     * @throws UnsupportedEncodingException if the Builder charset name is not supported
     * @throws InvalidKeySpecException      if the specified key specification cannot be used to
     *                                      generate a secret key
     * @throws NullPointerException         if the specified Builder secret key type is {@code null}
     */
    private SecretKey getSecretKey(char[] key) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(mBuilder.getSecretKeyType());
        KeySpec spec = new PBEKeySpec(key, mBuilder.getSalt().getBytes(mBuilder.getCharsetName()), mBuilder.getIterationCount(), mBuilder.getKeyLength());
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), mBuilder.getAlgorithm());
    }

    /**
     * takes in a simple string and performs an sha1 hash
     * that is 128 bits long...we then base64 encode it
     * and return the char array
     *
     * @param key simple inputted string
     *
     * @return sha1 base64 encoded representation
     *
     * @throws UnsupportedEncodingException if the Builder charset name is not supported
     * @throws NoSuchAlgorithmException     if the Builder digest algorithm is not available
     * @throws NullPointerException         if the Builder digest algorithm is {@code null}
     */
    private char[] hashTheKey(String key) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(mBuilder.getDigestAlgorithm());
        messageDigest.update(key.getBytes(mBuilder.getCharsetName()));
        return Base64.encodeToString(messageDigest.digest(), Base64.NO_PADDING).toCharArray();
    }

    /**
     * When you encrypt or decrypt in callback mode you get noticed of result using this interface
     */
    public static interface Callback {

        /**
         * Called when encrypt or decrypt job ends and the process was a success
         *
         * @param result the encrypted or decrypted String
         */
        public void onSuccess(String result);

        /**
         * Called when encrypt or decrypt job ends and has occurred an error in the process
         *
         * @param exception the Exception related to the error
         */
        public void onError(Exception exception);

    }

    /**
     * This class is used to create an Encryption instance, you should provide ALL data or start
     * with the Default Builder provided by the getDefaultBuilder method
     */
    public static class Builder {

        private byte[] mIv;
        private int mKeyLength;
        private int mBase64Mode;
        private int mIterationCount;
        private String mSalt;
        private String mKey;
        private String mAlgorithm;
        private String mCharsetName;
        private String mSecretKeyType;
        private String mDigestAlgorithm;
        private String mSecureRandomAlgorithm;
        private SecureRandom mSecureRandom;
        private IvParameterSpec mIvParameterSpec;

        /**
         * @return an default builder with the follow defaults:
         * the default char set is UTF-8
         * the default base mode is Base64
         * the Secret Key Type is the PBKDF2WithHmacSHA1
         * the default salt is "some_salt" but can be anything
         * the default length of key is 128
         * the default iteration count is 65536
         * the default algorithm is AES in CBC mode and PKCS 5 Padding
         * the default secure random algorithm is SHA1PRNG
         * the default message digest algorithm SHA1
         */
        public static Builder getDefaultBuilder(String key, String salt, byte[] iv) {
            return new Builder()
                    .setIv(iv)
                    .setKey(key)
                    .setSalt(salt)
                    .setKeyLength(128)
                    .setCharsetName("UTF8")
                    .setIterationCount(65536)
                    .setDigestAlgorithm("SHA1")
                    .setBase64Mode(Base64.DEFAULT)
                    .setAlgorithm("AES/CBC/PKCS5Padding")
                    .setSecureRandomAlgorithm("SHA1PRNG")
                    .setSecretKeyType("PBKDF2WithHmacSHA1");
        }

        /**
         * Build the Encryption with the provided information
         *
         * @return a new Encryption instance with provided information
         *
         * @throws NoSuchAlgorithmException if the specified SecureRandomAlgorithm is not available
         * @throws NullPointerException     if the SecureRandomAlgorithm is {@code null} or if the
         *                                  IV byte array is null
         */
        public Encryption build() throws NoSuchAlgorithmException {
            setSecureRandom(SecureRandom.getInstance(getSecureRandomAlgorithm()));
            setIvParameterSpec(new IvParameterSpec(getIv()));
            return new Encryption(this);
        }

        //region getters and setters

        /**
         * @return the charset name
         */
        private String getCharsetName() {
            return mCharsetName;
        }

        /**
         * @param charsetName the new charset name
         *
         * @return this instance to follow the Builder patter
         */
        public Builder setCharsetName(String charsetName) {
            mCharsetName = charsetName;
            return this;
        }

        /**
         * @return the algorithm
         */
        private String getAlgorithm() {
            return mAlgorithm;
        }

        /**
         * @param algorithm the algorithm to be used
         *
         * @return this instance to follow the Builder patter
         */
        public Builder setAlgorithm(String algorithm) {
            mAlgorithm = algorithm;
            return this;
        }

        /**
         * @return the Base 64 mode
         */
        private int getBase64Mode() {
            return mBase64Mode;
        }

        /**
         * @param base64Mode set the base 64 mode
         *
         * @return this instance to follow the Builder patter
         */
        public Builder setBase64Mode(int base64Mode) {
            mBase64Mode = base64Mode;
            return this;
        }

        /**
         * @return the type of aes key that will be created, on KITKAT+ the API has changed, if you
         * are getting problems please @see <a href="http://android-developers.blogspot.com.br/2013/12/changes-to-secretkeyfactory-api-in.html">http://android-developers.blogspot.com.br/2013/12/changes-to-secretkeyfactory-api-in.html</a>
         */
        private String getSecretKeyType() {
            return mSecretKeyType;
        }

        /**
         * @param secretKeyType the type of AES key that will be created, on KITKAT+ the API has
         *                      changed, if you are getting problems please @see <a href="http://android-developers.blogspot.com.br/2013/12/changes-to-secretkeyfactory-api-in.html">http://android-developers.blogspot.com.br/2013/12/changes-to-secretkeyfactory-api-in.html</a>
         *
         * @return this instance to follow the Builder patter
         */
        public Builder setSecretKeyType(String secretKeyType) {
            mSecretKeyType = secretKeyType;
            return this;
        }

        /**
         * @return the value used for salting
         */
        private String getSalt() {
            return mSalt;
        }

        /**
         * @param salt the value used for salting
         *
         * @return this instance to follow the Builder patter
         */
        public Builder setSalt(String salt) {
            mSalt = salt;
            return this;
        }

        /**
         * @return the key
         */
        private String getKey() {
            return mKey;
        }

        /**
         * @param key the key.
         *
         * @return this instance to follow the Builder patter
         */
        public Builder setKey(String key) {
            mKey = key;
            return this;
        }

        /**
         * @return the length of key
         */
        private int getKeyLength() {
            return mKeyLength;
        }

        /**
         * @param keyLength the length of key
         *
         * @return this instance to follow the Builder patter
         */
        public Builder setKeyLength(int keyLength) {
            mKeyLength = keyLength;
            return this;
        }

        /**
         * @return the number of times the password is hashed
         */
        private int getIterationCount() {
            return mIterationCount;
        }

        /**
         * @param iterationCount the number of times the password is hashed
         *
         * @return this instance to follow the Builder patter
         */
        public Builder setIterationCount(int iterationCount) {
            mIterationCount = iterationCount;
            return this;
        }

        /**
         * @return the algorithm used to generate the secure random
         */
        private String getSecureRandomAlgorithm() {
            return mSecureRandomAlgorithm;
        }

        /**
         * @param secureRandomAlgorithm the algorithm to generate the secure random
         *
         * @return this instance to follow the Builder patter
         */
        public Builder setSecureRandomAlgorithm(String secureRandomAlgorithm) {
            mSecureRandomAlgorithm = secureRandomAlgorithm;
            return this;
        }

        /**
         * @return the IvParameterSpec bytes array
         */
        private byte[] getIv() {
            return mIv;
        }

        /**
         * @param iv the byte array to create a new IvParameterSpec
         *
         * @return this instance to follow the Builder patter
         */
        public Builder setIv(byte[] iv) {
            mIv = iv;
            return this;
        }

        /**
         * @return the SecureRandom
         */
        private SecureRandom getSecureRandom() {
            return mSecureRandom;
        }

        /**
         * @param secureRandom the Secure Random
         *
         * @return this instance to follow the Builder patter
         */
        public Builder setSecureRandom(SecureRandom secureRandom) {
            mSecureRandom = secureRandom;
            return this;
        }

        /**
         * @return the IvParameterSpec
         */
        private IvParameterSpec getIvParameterSpec() {
            return mIvParameterSpec;
        }

        /**
         * @param ivParameterSpec the IvParameterSpec
         *
         * @return this instance to follow the Builder patter
         */
        public Builder setIvParameterSpec(IvParameterSpec ivParameterSpec) {
            mIvParameterSpec = ivParameterSpec;
            return this;
        }

        /**
         * @return the message digest algorithm
         */
        private String getDigestAlgorithm() {
            return mDigestAlgorithm;
        }

        /**
         * @param digestAlgorithm the algorithm to be used to get message digest instance
         *
         * @return this instance to follow the Builder patter
         */
        public Builder setDigestAlgorithm(String digestAlgorithm) {
            mDigestAlgorithm = digestAlgorithm;
            return this;
        }

        //endregion

    }

}
    
}
