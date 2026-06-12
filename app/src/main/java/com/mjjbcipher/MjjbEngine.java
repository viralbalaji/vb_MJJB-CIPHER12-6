package com.mjjbcipher;


/**
 * JNI bridge to the native MJJB cipher engine (mjjb_cipher.cpp).
 * All cipher logic runs in the NDK — no Java crypto used.
 */
public class MjjbEngine {


    static {
        System.loadLibrary("mjjbcipher");
    }


    /**
     * Start encode or decode in a background native thread.
     
     * @param inPath    absolute path to input file
     * @param tempDir   absolute path to temp directory (with trailing /)
     * @param outDir    absolute path to output directory (no trailing /)
     * @param key1      key 1 string (alphanumeric)
     * @param key2      key 2 string (alphanumeric)
     * @param k1Base    "dec" or "oct"
     * @param k2Base    "dec" or "oct"
     * @param structure 0=EES, 1=ESE, 2=SEE
     * @param blockSize block size in bytes (57–56789)
     * @param mode      "encode", "decode", or "auto"
     * @return output filename (just the name, not full path) or "ERROR: ..."
     */

    public native String startProcess(
        String inPath, String tempDir, String outDir,
        String key1, String key2,
        String k1Base, String k2Base,
        int structure, int blockSize, String mode);


    /**
     * Poll progress — returns JSON string with same fields as PC /progress endpoint.
     * Safe to call from any thread (reads volatile globals).
     */
    public native String getProgress();

    /**
     * Returns true if the file at path has the MJJB sentinel header.
     * Identical check to PC's probe_mjjb_sentinel().
     */
    public native boolean probeIsMjjb(String path);

    /**
     * Returns the expected output filename for a given input name and operation.
     */
    public native String makeOutputName(String fname, boolean doEncode);
  /**CLAUDE,CLAUDE,CLAUDE,CLAUDE,CLAUDE,CLAUDE,CG,CG,CG,DS*/
}