package com.mjjbcipher;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.FileProvider;
import android.content.ContentValues;
import android.provider.MediaStore;
import android.os.Environment;

import java.io.*;
import java.nio.file.Files;

/**
 * MainActivity — hosts the WebView showing MJJB_CIPHER_2.html (offline, from assets).
 * JavaScript calls go through MjjbBridge which calls MjjbEngine (NDK).
 */
public class MainActivity extends AppCompatActivity {

    private static final int PICK_FILE_REQUEST = 1;
    private Uri mPendingUri = null;

    private WebView   mWebView;
    private MjjbBridge mBridge;

    // Paths
    private File mTempDir;
    private File mOutputDir;
    private File mInputDir;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Dirs
        mTempDir   = new File(getCacheDir(),     "temp");
        mOutputDir = new File(getFilesDir(),     "output");
        mInputDir  = getExternalFilesDir(null);   // Android/data/com.mjjbcipher/files/
        mTempDir.mkdirs();
        mOutputDir.mkdirs();
        if (mInputDir != null) mInputDir.mkdirs();

        // WebView — NO network access (no cleartext, no internet permission)
        mWebView = new WebView(this);
        setContentView(mWebView);

        WebSettings ws = mWebView.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setAllowFileAccessFromFileURLs(true);
        ws.setAllowUniversalAccessFromFileURLs(true);
        ws.setDomStorageEnabled(true);
        ws.setLoadWithOverviewMode(true);
        ws.setUseWideViewPort(true);
        ws.setBuiltInZoomControls(false);
        ws.setDisplayZoomControls(false);
        // Explicitly block network
        ws.setBlockNetworkImage(false); // local SVG logos are ok
        ws.setBlockNetworkLoads(true);  // block all remote network loads

        mWebView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(android.webkit.WebView view, String url) {
                super.onPageFinished(view, url);
                if (mPendingUri != null) {
                    deliverFileToWebView(mPendingUri);
                    mPendingUri = null;
                }
            }
        });
        mWebView.setWebChromeClient(new WebChromeClient());

        mBridge = new MjjbBridge();
        mWebView.addJavascriptInterface(mBridge, "Android");

        // Load the bundled HTML from assets
        mWebView.loadUrl("file:///android_asset/mjjb_ui.html");

        // Handle incoming shared file
        handleIncomingIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIncomingIntent(intent);
    }

    private void handleIncomingIntent(Intent intent) {
        if (intent == null) return;
        if (Intent.ACTION_SEND.equals(intent.getAction())) {
            Uri uri = intent.getParcelableExtra(Intent.EXTRA_STREAM);
            if (uri != null) mPendingUri = uri;
        }
    }

    // ─── File picker ───
    public void openFilePicker() {
        Intent i = new Intent(Intent.ACTION_GET_CONTENT);
        i.setType("*/*");
        i.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(Intent.createChooser(i, "Select File"), PICK_FILE_REQUEST);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PICK_FILE_REQUEST && resultCode == Activity.RESULT_OK && data != null) {
            deliverFileToWebView(data.getData());
        }
    }

    private void deliverFileToWebView(Uri uri) {
        try {
            String name = queryFileName(uri);
            long   size = queryFileSize(uri);

            final String safeName = (name != null && !name.isEmpty()) ? name : ("picked_input_" + System.currentTimeMillis());

            // Copy to temp dir so NDK can access via native path
            File dest = new File(mTempDir, safeName);
            try (InputStream is = getContentResolver().openInputStream(uri);
                 FileOutputStream os = new FileOutputStream(dest)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = is.read(buf)) > 0) os.write(buf, 0, n);
            }

            final String absPath = dest.getAbsolutePath();

            // Notify JS
            runOnUiThread(() -> mWebView.evaluateJavascript(
                "window.androidDeliverFile('" +
                escapeJs(absPath) + "','" +
                escapeJs(safeName) + "'," +
                size + ")", null));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String queryFileName(Uri uri) {
        try (Cursor c = getContentResolver().query(uri, null, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) return c.getString(idx);
            }
        } catch (Exception ignored) {}
        String path = uri.getPath();
        return (path != null) ? path.substring(path.lastIndexOf('/') + 1) : "file";
    }

    private long queryFileSize(Uri uri) {
        try (Cursor c = getContentResolver().query(uri, null, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.SIZE);
                if (idx >= 0) return c.getLong(idx);
            }
        } catch (Exception ignored) {}
        return 0;
    }

    // Escape string for safe JS injection
    private static String escapeJs(String s) {
        return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n");
    }

    // ─── Save output file to Downloads/MJJB-CIPHER/ via MediaStore (API 29+) ───
    private void shareOutputFile(String absPath) {
        File src = new File(absPath);
        if (!src.exists()) return;

        ContentValues cv = new ContentValues();
        cv.put(MediaStore.Downloads.DISPLAY_NAME, src.getName());
        cv.put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream");
        cv.put(MediaStore.Downloads.RELATIVE_PATH,
               Environment.DIRECTORY_DOWNLOADS + "/MJJB-CIPHER");

        Uri collection = MediaStore.Downloads.getContentUri(
                MediaStore.VOLUME_EXTERNAL_PRIMARY);
        Uri itemUri = getContentResolver().insert(collection, cv);

        if (itemUri == null) {
            android.widget.Toast.makeText(this,
                "Save failed — could not create file",
                android.widget.Toast.LENGTH_LONG).show();
            return;
        }

        try (java.io.InputStream in  = new java.io.FileInputStream(src);
             java.io.OutputStream out = getContentResolver().openOutputStream(itemUri)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        } catch (Exception e) {
            e.printStackTrace();
            android.widget.Toast.makeText(this,
                "Save failed: " + e.getMessage(),
                android.widget.Toast.LENGTH_LONG).show();
            return;
        }

        android.widget.Toast.makeText(this,
            "Saved to Downloads/MJJB-CIPHER/" + src.getName(),
            android.widget.Toast.LENGTH_LONG).show();
    }

    /** Finds a file by name in inputDir first, then outputDir. */
    private File resolveFile(String filename) {
        if (mInputDir != null) {
            File f = new File(mInputDir, filename);
            if (f.exists()) return f;
        }
        File f = new File(mOutputDir, filename);
        return f.exists() ? f : null;
    }

    // ═══════════════════════════════════════════
    // JS BRIDGE
    // ═══════════════════════════════════════════
    public class MjjbBridge {

        private final MjjbEngine engine = new MjjbEngine();
        private final Handler    main   = new Handler(Looper.getMainLooper());
        private String  mLastOutputPath = null;

        /** Called from JS — opens native file picker */
        @JavascriptInterface
        public void pickFile() {
            main.post(() -> openFilePicker());
        }

        /**
         * Called from JS to start encode/decode.
         * Returns output filename or "ERROR:..."
         */
        @JavascriptInterface
        public String startProcess(String inPath, String key1, String key2,
                                   String k1Base, String k2Base,
                                   int structure, int blockSize, String mode) {
            String tempPath   = mTempDir.getAbsolutePath()   + "/";
            String outputPath = mOutputDir.getAbsolutePath();
            String result = engine.startProcess(
                inPath, tempPath, outputPath,
                key1, key2, k1Base, k2Base,
                structure, blockSize, mode);
            if (!result.startsWith("ERROR")) {
                mLastOutputPath = outputPath + "/" + result;
            }
            return result;
        }

        /** Poll progress JSON — same format as PC's /progress response */
        @JavascriptInterface
        public String getProgress() {
            return engine.getProgress();
        }

        /** Check if file is MJJB encoded */
        @JavascriptInterface
        public boolean probeIsMjjb(String path) {
            return engine.probeIsMjjb(path);
        }

        /** Get expected output name */
        @JavascriptInterface
        public String makeOutputName(String fname, boolean doEncode) {
            return engine.makeOutputName(fname, doEncode);
        }

        /** Share/save the last output file via Android share sheet */
        @JavascriptInterface
        public void shareOutput() {
            if (mLastOutputPath != null) {
                main.post(() -> shareOutputFile(mLastOutputPath));
            }
        }

        
        /** Get output dir path for reading back file info */
        @JavascriptInterface
        public String getOutputPath() {
            return mOutputDir.getAbsolutePath();
        }

        /**
         * List all files in the private output directory.
         * Returns JSON array: [{name, size, lastModified}, ...]  sorted newest first.
         */
         @JavascriptInterface
         public String listOutputFiles() {
             java.util.List<File> all = new java.util.ArrayList<>();
             File[] outFiles = mOutputDir.listFiles();
             if (outFiles != null) for (File f : outFiles) all.add(f);
             if (mInputDir != null) {
                 File[] inFiles = mInputDir.listFiles();
                 if (inFiles != null) for (File f : inFiles) all.add(f);
             }
             all.sort((a, b) -> Long.compare(b.lastModified(), a.lastModified()));
             File[] files = all.toArray(new File[0]);
             if (files.length == 0) return "[]";
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < files.length; i++) {
                File f = files[i];
                if (i > 0) sb.append(",");
                sb.append("{\"name\":\"").append(escJs(f.getName()))
                  .append("\",\"size\":").append(f.length())
                  .append(",\"lastModified\":").append(f.lastModified())
                  .append("}");
            }
            sb.append("]");
            return sb.toString();
        }

        /** Delete a file from the private output directory. Returns true on success. */
        @JavascriptInterface
        public boolean deleteOutputFile(String filename) {
            File f = resolveFile(filename);
            return f != null && f.exists() && f.delete();
        }

        /**
         * Save a file from the private output directory to
         * Downloads/MJJB-CIPHER/ via MediaStore.
         */
        @JavascriptInterface
        public void downloadOutputFile(String filename) {
            File f = resolveFile(filename);
            if (f != null) main.post(() -> shareOutputFile(f.getAbsolutePath()));
        }

        /** Returns the directory path that contains the named file */
        @JavascriptInterface
        public String resolveFileDir(String filename) {
            if (mInputDir != null) {
                File f = new File(mInputDir, filename);
                if (f.exists()) return mInputDir.getAbsolutePath();
            }
            return mOutputDir.getAbsolutePath();
        }
        /**
         * Open a file from the private output directory with an Intent
         * so the user can pick an app (Open With chooser).
         */
         @JavascriptInterface
         public void openOutputFileWith(String filename) {
             main.post(() -> {
                 File f = resolveFile(filename);
                 if (f == null || !f.exists()) return;
                try {
                    Uri uri = androidx.core.content.FileProvider.getUriForFile(
                        MainActivity.this,
                        getPackageName() + ".provider", f);
                    Intent intent = new Intent(Intent.ACTION_VIEW);
                    intent.setData(uri);
                    intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    startActivity(Intent.createChooser(intent, "Open with"));
                } catch (Exception e) { e.printStackTrace(); }
            });
        }

        private String escJs(String s) {
            return s.replace("\\", "\\\\").replace("\"", "\\\"");
        }
    }



    //  ===========  11,12-6-2026  CLAUD,CLAUDE
  /**CLAUDE,CLAUDE,CLAUDE,CLAUDE,CLAUDE,CLAUDE,CG,CG,CG,DS*/



    @Override
    public void onBackPressed() {
        if (mWebView.canGoBack()) mWebView.goBack();
        else super.onBackPressed();
    }
}