// mjjb_cipher.cpp — MJJB Cipher Engine for Android NDK
// Ported from MJJB_CIPHER_2.cpp (Windows) → Android JNI
// All logic is IDENTICAL to the PC version for cross-platform compatibility.
// No Windows APIs (no winsock, no CryptGenRandom) — uses POSIX + JNI.

#include <jni.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <chrono>
#include <thread>
#include <sys/stat.h>
#include <android/log.h>

#define LOG_TAG "MJJB"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ─────────────────────────────────────────────
// CONSTANTS  (identical to PC version)
// ─────────────────────────────────────────────
static const uint32_t MODULO   = 256;
static const size_t   IO_BUF   = 4ULL * 1024 * 1024; // 4 MB (mobile-friendly)

// ─────────────────────────────────────────────
// SENTINEL  (MUST be byte-for-byte identical to PC version)
// ─────────────────────────────────────────────
static const char MJJB_SENT_PRE[]  =
    "[{ (\"MJJB-INTERNATIONAL ENCODING / DECODING CIPHER\") :";
static const char MJJB_SENT_POST[] =
    "\n(\"CIPHERed BY: VAGHASIYA OM VIRALBHAI, in association with: \n"
    "\"MOTI-JIMMY-JEBO-BOOSHIYAA & CLAUDE,CG @ 02-05-2026\"\") }]\n";

static const size_t SENT_PRE_LEN  = sizeof(MJJB_SENT_PRE)  - 1;
static const size_t SENT_POST_LEN = sizeof(MJJB_SENT_POST) - 1;
static const size_t SENTINEL_LEN  = SENT_PRE_LEN + 4 + SENT_POST_LEN;

// ─────────────────────────────────────────────
// PROGRESS STATE (thread-safe via atomic-ish globals for JNI polling)
// ─────────────────────────────────────────────
static volatile bool   g_running   = false;
static volatile bool   g_finished  = false;
static volatile bool   g_has_error = false;
static volatile double g_percent   = 0.0;
static volatile uint64_t g_done_bytes  = 0;
static volatile uint64_t g_total_bytes = 0;
static volatile uint64_t g_done_blocks  = 0;
static volatile uint64_t g_total_blocks = 0;
static volatile double g_mbps      = 0.0;
static char   g_status[512]        = "idle";

static void prog_set(const char* msg, uint64_t db, uint64_t tb, uint64_t dblk, uint64_t tblk) {
    g_done_bytes   = db;
    g_total_bytes  = tb;
    g_done_blocks  = dblk;
    g_total_blocks = tblk;
    g_percent      = (tb > 0) ? (100.0 * db / tb) : 0.0;
    strncpy(g_status, msg, sizeof(g_status)-1);
}

static void prog_finish(bool ok, const char* msg, double mbps) {
    g_running   = false;
    g_finished  = true;
    g_has_error = !ok;
    g_mbps      = mbps;
    g_percent   = ok ? 100.0 : g_percent;
    strncpy(g_status, msg, sizeof(g_status)-1);
}

// ─────────────────────────────────────────────
// SENTINEL WRITE / READ  (identical byte layout to PC)
// ─────────────────────────────────────────────
static void write_sentinel(std::ostream& dst, uint32_t rs) {
    uint8_t le[4] = {
        (uint8_t)(rs & 0xFF),
        (uint8_t)((rs >> 8)  & 0xFF),
        (uint8_t)((rs >> 16) & 0xFF),
        (uint8_t)((rs >> 24) & 0xFF)
    };
    dst.write(MJJB_SENT_PRE, SENT_PRE_LEN);
    dst.write((char*)le,     4);
    dst.write(MJJB_SENT_POST, SENT_POST_LEN);
}

static bool read_sentinel(std::istream& src, uint32_t& rs) {
    std::vector<char> pre(SENT_PRE_LEN), post(SENT_POST_LEN);
    uint8_t le[4];
    src.read(pre.data(),  SENT_PRE_LEN);
    src.read((char*)le,   4);
    src.read(post.data(), SENT_POST_LEN);
    rs = (uint32_t)le[0]
       | ((uint32_t)le[1] << 8)
       | ((uint32_t)le[2] << 16)
       | ((uint32_t)le[3] << 24);
    return (memcmp(pre.data(),  MJJB_SENT_PRE,  SENT_PRE_LEN)  == 0 &&
            memcmp(post.data(), MJJB_SENT_POST, SENT_POST_LEN) == 0);
}

// ─────────────────────────────────────────────
// FILE UTILITIES
// ─────────────────────────────────────────────
static uint64_t file_size_of(const std::string& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) return 0;
    return (uint64_t)f.tellg();
}

static void safe_rename(const std::string& tmp, const std::string& final_p) {
    ::rename(final_p.c_str(), (final_p + ".bak").c_str());
    ::rename(tmp.c_str(), final_p.c_str());
    ::remove((final_p + ".bak").c_str());
}

static void verify_size(const std::string& path, uint64_t expected) {
    uint64_t actual = file_size_of(path);
    if (actual != expected)
        throw std::runtime_error("INTEGRITY FAIL: " + path +
            " expected=" + std::to_string(expected) +
            " got=" + std::to_string(actual));
}

static void silent_rm(const std::string& p) { ::remove(p.c_str()); }

// ─────────────────────────────────────────────
// KEY UTILITIES  (identical to PC)
// ─────────────────────────────────────────────
static std::vector<uint8_t> to_values(const std::string& k, const std::string& base) {
    std::vector<uint8_t> v;
    for (char c : k) {
        uint8_t code = (uint8_t)c;
        if (base == "oct") {
            char buf[8]; snprintf(buf, sizeof(buf), "%o", (unsigned)code);
            uint32_t oct_as_dec = (uint32_t)strtoul(buf, nullptr, 10);
            v.push_back((uint8_t)(oct_as_dec % 256));
        } else {
            v.push_back(code);
        }
    }
    return v;
}

static uint32_t calc_shift(const std::vector<uint8_t>& sk,
                            const std::vector<uint8_t>& ok,
                            uint32_t BLOCK_SIZE) {
    uint64_t total = 0;
    uint32_t si = 0, oi = 0;
    bool use_s = true;
    for (uint32_t r = 0; r < BLOCK_SIZE; ++r) {
        if (use_s) {
            total += sk[si++];
            if (si >= sk.size()) { si = 0; use_s = false; }
        } else {
            total += ok[oi++];
            if (oi >= ok.size()) { oi = 0; use_s = true; }
        }
    }
    return (uint32_t)(total % BLOCK_SIZE);
}

// ─────────────────────────────────────────────
// E-STAGE  (identical logic to PC)
// ─────────────────────────────────────────────
static void do_e_stage(const std::string& in_path,
                        const std::string& out_path,
                        const std::vector<uint8_t>& key,
                        uint64_t process_bytes,
                        bool decode,
                        uint64_t prog_base, uint64_t prog_total,
                        uint64_t blk_total,
                        const char* label)
{
    std::string tmp = out_path + ".tmp";
    silent_rm(tmp);

    std::ifstream in(in_path,  std::ios::binary);
    std::ofstream out(tmp,     std::ios::binary);
    if (!in)  throw std::runtime_error("E-stage open fail: "   + in_path);
    if (!out) throw std::runtime_error("E-stage create fail: " + tmp);

    const size_t klen = key.size();
    uint64_t idx = 0, written = 0, prog_rep = 0;
    const uint64_t REP = 1ULL * 1024 * 1024;
    std::vector<uint8_t> work(IO_BUF);

    uint64_t rem = process_bytes;
    while (rem > 0) {
        size_t want = (size_t)std::min((uint64_t)IO_BUF, rem);
        in.read((char*)work.data(), want);
        std::streamsize got = in.gcount();
        if (got <= 0) throw std::runtime_error("E-stage EOF: " + in_path);

        for (std::streamsize i = 0; i < got; ++i) {
            uint8_t b = work[i];
            b = decode ? (b - key[idx % klen] + MODULO) % MODULO
                       : (b + key[idx % klen]) % MODULO;
            work[i] = b;
            ++idx;
        }
        out.write((char*)work.data(), got);
        if (!out) throw std::runtime_error("E-stage write fail: " + tmp);

        written  += got;
        rem      -= got;
        prog_rep += got;
        if (prog_rep >= REP) {
            prog_set(label, prog_base + written, prog_total, written, blk_total);
            prog_rep = 0;
        }
    }
    out.flush(); out.close(); in.close();
    verify_size(tmp, process_bytes);
    safe_rename(tmp, out_path);
}

// ─────────────────────────────────────────────
// S-STAGE  (identical logic to PC)
// ─────────────────────────────────────────────
static void do_s_stage(const std::string& in_path,
                        const std::string& out_path,
                        uint32_t shift,
                        uint64_t num_blocks,
                        uint32_t BLOCK_SIZE,
                        uint64_t prog_base, uint64_t prog_total,
                        uint64_t blk_total,
                        const char* label)
{
    std::string tmp = out_path + ".tmp";
    silent_rm(tmp);

    std::ifstream in(in_path,  std::ios::binary);
    std::ofstream out(tmp,     std::ios::binary);
    if (!in)  throw std::runtime_error("S-stage open fail: "   + in_path);
    if (!out) throw std::runtime_error("S-stage create fail: " + tmp);

    const uint64_t BPP = IO_BUF / BLOCK_SIZE;
    std::vector<uint8_t> cin(BPP * BLOCK_SIZE);
    std::vector<uint8_t> cout_(BPP * BLOCK_SIZE);

    uint64_t blk_done = 0, written = 0, prog_rep = 0;
    const uint64_t REP = 1ULL * 1024 * 1024;

    while (blk_done < num_blocks) {
        uint64_t wb  = std::min(BPP, num_blocks - blk_done);
        uint64_t wby = wb * BLOCK_SIZE;

        in.read((char*)cin.data(), wby);
        if ((uint64_t)in.gcount() != wby)
            throw std::runtime_error("S-stage EOF: " + in_path);

        for (uint64_t b = 0; b < wb; ++b) {
            const uint8_t* src = cin.data()  + b * BLOCK_SIZE;
            uint8_t*       dst = cout_.data() + b * BLOCK_SIZE;
            for (uint32_t i = 0; i < BLOCK_SIZE; ++i)
                dst[(i + shift) % BLOCK_SIZE] = src[i];
        }

        out.write((char*)cout_.data(), wby);
        if (!out) throw std::runtime_error("S-stage write fail: " + tmp);

        blk_done  += wb;
        written   += wby;
        prog_rep  += wby;
        if (prog_rep >= REP) {
            prog_set(label, prog_base + written, prog_total, blk_done, blk_total);
            prog_rep = 0;
        }
    }
    out.flush(); out.close(); in.close();
    verify_size(tmp, num_blocks * BLOCK_SIZE);
    safe_rename(tmp, out_path);
}

// ─────────────────────────────────────────────
// SPLIT  (identical to PC)
// ─────────────────────────────────────────────
static void split_input(const std::string& src,
                         const std::string& full_path,
                         const std::string& rem_path,
                         uint64_t full_bytes,
                         uint32_t rem_size)
{
    std::ifstream fin(src, std::ios::binary);
    if (!fin) throw std::runtime_error("Cannot open input: " + src);

    {
        std::string tmp = full_path + ".tmp";
        std::ofstream fout(tmp, std::ios::binary);
        uint64_t left = full_bytes;
        std::vector<char> wbuf(IO_BUF);
        while (left > 0) {
            size_t want = (size_t)std::min((uint64_t)IO_BUF, left);
            fin.read(wbuf.data(), want);
            std::streamsize got = fin.gcount();
            if (got <= 0) throw std::runtime_error("split_input: read fail");
            fout.write(wbuf.data(), got);
            left -= got;
        }
        fout.flush(); fout.close();
        verify_size(tmp, full_bytes);
        safe_rename(tmp, full_path);
    }

    if (rem_size > 0) {
        std::string tmp = rem_path + ".tmp";
        std::vector<char> rbuf(rem_size);
        fin.read(rbuf.data(), rem_size);
        if ((uint32_t)fin.gcount() != rem_size)
            throw std::runtime_error("split_input: remainder read fail");
        std::ofstream rf(tmp, std::ios::binary);
        rf.write(rbuf.data(), rem_size);
        rf.flush(); rf.close();
        verify_size(tmp, rem_size);
        safe_rename(tmp, rem_path);
    }
}

// Android CSPRNG padding (uses /dev/urandom — equivalent to Windows CryptGenRandom)
static void csprng_fill(uint8_t* buf, size_t len) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) { fread(buf, 1, len, f); fclose(f); }
}

// Output filename logic (NOT-identical to PC)  @  11-06-2026 CLAUDE
static std::string make_output_name(const std::string& fname, bool do_enc) {
    if (do_enc) {
        // ENCODE: photo.jpg → photo.mjjb.jpg  (real ext preserved, no app opens it directly)
        size_t dot = fname.rfind('.');
        if (dot != std::string::npos)
            return fname.substr(0, dot) + ".mjjb" + fname.substr(dot);
        return fname + ".mjjb";
    }
    // DECODE: strip ".mjjb" segment to restore original name
    size_t mjjb = fname.rfind(".mjjb.");
    if (mjjb != std::string::npos)
        return fname.substr(0, mjjb) + fname.substr(mjjb + 5); // skip ".mjjb"
    const std::string suf = ".mjjb";
    if (fname.size() > suf.size() &&
        fname.substr(fname.size() - suf.size()) == suf)
        return fname.substr(0, fname.size() - suf.size());
    size_t dot = fname.rfind('.');
    if (dot != std::string::npos)
        return fname.substr(0, dot) + "_decoded" + fname.substr(dot);
    return fname + "_decoded";
}

// ─────────────────────────────────────────────
// ENCODE PIPELINE  (identical logic to PC)
// ─────────────────────────────────────────────
static std::string run_encode(const std::string& in_path,
                               const std::string& temp_dir,
                               const std::string& out_path,
                               const std::vector<uint8_t>& k1,
                               const std::vector<uint8_t>& k2,
                               int structure,
                               uint32_t BLOCK_SIZE)
{
    std::string op;
    switch (structure) { case 0: op="EESr"; break; case 2: op="SEEr"; break; default: op="ESEr"; }
    std::string root = temp_dir + op + "/";
    // create dir
    ::mkdir(root.c_str(), 0755);

    uint64_t fsz      = file_size_of(in_path);
    uint64_t num_full = fsz / BLOCK_SIZE;
    uint32_t rem_size = (uint32_t)(fsz % BLOCK_SIZE);
    uint64_t full_b   = num_full * BLOCK_SIZE;
    if (num_full == 0) throw std::runtime_error("No full blocks — file too small for block size");

    std::string p_raw = root + "RAW_full.bin";
    std::string p_rem = root + "ex_" + op;
    std::string p_op1 = root + "OP1_" + op + ".bin";
    std::string p_op2 = root + "OP2_" + op + ".bin";
    std::string p_op3 = root + "OP3_" + op + ".bin";

    uint64_t prog_total = full_b * 3;

    g_running = true; g_finished = false; g_has_error = false;
    g_done_bytes = 0; g_total_bytes = prog_total;
    g_done_blocks = 0; g_total_blocks = num_full;
    auto t_start = std::chrono::steady_clock::now();
    prog_set("Splitting input...", 0, prog_total, 0, num_full);

    split_input(in_path, p_raw, p_rem, full_b, rem_size);

    // Append padded remainder block (CSPRNG — same as PC CryptGenRandom)
    if (rem_size > 0) {
        std::vector<uint8_t> rem_buf(BLOCK_SIZE, 0);
        { std::ifstream rf(p_rem, std::ios::binary); rf.read((char*)rem_buf.data(), rem_size); }
        csprng_fill(rem_buf.data() + rem_size, BLOCK_SIZE - rem_size);
        std::ofstream af(p_raw, std::ios::binary | std::ios::app);
        af.write((char*)rem_buf.data(), BLOCK_SIZE);
        af.flush();
        num_full += 1;
        full_b   += BLOCK_SIZE;
        prog_total = full_b * 3;
        g_total_bytes = prog_total;
        g_total_blocks = num_full;
    }

    uint32_t shift_enc = calc_shift(k2, k1, BLOCK_SIZE);

    if (structure == 0) {
        do_e_stage(p_raw, p_op1, k1, full_b, false, 0,         prog_total, num_full, "E(K1) - Stage 1/3");
        do_e_stage(p_op1, p_op2, k2, full_b, false, full_b,    prog_total, num_full, "E(K2) - Stage 2/3");
        do_s_stage(p_op2, p_op3, shift_enc, num_full, BLOCK_SIZE, full_b*2, prog_total, num_full, "S(K2,K1) - Stage 3/3");
    } else if (structure == 1) {
        do_e_stage(p_raw, p_op1, k1, full_b, false, 0,         prog_total, num_full, "E(K1) - Stage 1/3");
        do_s_stage(p_op1, p_op2, shift_enc, num_full, BLOCK_SIZE, full_b,    prog_total, num_full, "S(K2,K1) - Stage 2/3");
        do_e_stage(p_op2, p_op3, k1, full_b, false, full_b*2,  prog_total, num_full, "E(K1) - Stage 3/3");
    } else {
        do_s_stage(p_raw, p_op1, shift_enc, num_full, BLOCK_SIZE, 0,         prog_total, num_full, "S(K2,K1) - Stage 1/3");
        do_e_stage(p_op1, p_op2, k2, full_b, false, full_b,    prog_total, num_full, "E(K2) - Stage 2/3");
        do_e_stage(p_op2, p_op3, k1, full_b, false, full_b*2,  prog_total, num_full, "E(K1) - Stage 3/3");
    }

    prog_set("Writing output...", prog_total, prog_total, num_full, num_full);

    {
        std::string tmp = out_path + ".tmp";
        std::ifstream src_f(p_op3, std::ios::binary);
        std::ofstream dst_f(tmp,   std::ios::binary);
        write_sentinel(dst_f, rem_size);
        std::vector<char> buf(IO_BUF);
        while (src_f.read(buf.data(), IO_BUF) || src_f.gcount() > 0)
            dst_f.write(buf.data(), src_f.gcount());
        dst_f.put('\n');
        write_sentinel(dst_f, rem_size);
        dst_f.flush(); dst_f.close(); src_f.close();
        safe_rename(tmp, out_path);
    }

    { auto t_end = std::chrono::steady_clock::now();
      double secs = std::chrono::duration<double>(t_end - t_start).count();
      double mbps = (secs > 0) ? (full_b / 1048576.0) / secs : 0.0;
      prog_finish(true, "Done!", mbps); }
    // clean temp
    for (auto& p : {p_raw, p_rem, p_op1, p_op2, p_op3}) silent_rm(p);
    return out_path;
}

// ─────────────────────────────────────────────
// DECODE PIPELINE  (identical logic to PC)
// ─────────────────────────────────────────────
static std::string run_decode(const std::string& in_path,
                               const std::string& temp_dir,
                               const std::string& out_path,
                               const std::vector<uint8_t>& k1,
                               const std::vector<uint8_t>& k2,
                               int structure,
                               uint32_t BLOCK_SIZE)
{
    std::string op;
    switch (structure) { case 0: op="EESr"; break; case 2: op="SEEr"; break; default: op="ESEr"; }
    std::string root = temp_dir + op + "_dec/";
    ::mkdir(root.c_str(), 0755);

    g_running = true; g_finished = false; g_has_error = false;
    auto t_start = std::chrono::steady_clock::now();
    prog_set("Reading sentinel...", 0, 1, 0, 1);

    uint32_t rem_header = 0, rem_footer = 0;
    bool hdr_ok, ftr_ok;
    {
        std::ifstream hf(in_path, std::ios::binary);
        hdr_ok = read_sentinel(hf, rem_header);
        uint64_t fsz_sentinel = file_size_of(in_path);
        hf.seekg(-(int64_t)SENTINEL_LEN, std::ios::end);
        ftr_ok = read_sentinel(hf, rem_footer);
    }
    if (!hdr_ok || !ftr_ok || rem_header != rem_footer)
        LOGI("WARNING: Sentinel mismatch — data may be corrupted");
    uint32_t rem_size = rem_footer;

    // Strip header/footer
    std::string stripped = temp_dir + "stripped_input.bin";
    {
        std::ifstream sf(in_path, std::ios::binary);
        sf.seekg(0, std::ios::end);
        uint64_t total_sz = sf.tellg();
        uint64_t strip_sz = total_sz - (SENTINEL_LEN * 2) - 1;
        sf.seekg((int64_t)SENTINEL_LEN, std::ios::beg);
        std::ofstream of(stripped, std::ios::binary);
        std::vector<char> buf(IO_BUF);
        uint64_t left = strip_sz;
        while (left > 0) {
            size_t want = (size_t)std::min((uint64_t)IO_BUF, left);
            sf.read(buf.data(), want);
            of.write(buf.data(), sf.gcount());
            left -= sf.gcount();
        }
        of.flush();
    }

    uint64_t fsz      = file_size_of(stripped);
    uint64_t num_full = fsz / BLOCK_SIZE;
    uint64_t full_b   = num_full * BLOCK_SIZE;

    std::string p_raw = root + "RAW_full.bin";
    std::string p_op1 = root + "DOP1_" + op + ".bin";
    std::string p_op2 = root + "DOP2_" + op + ".bin";
    std::string p_op3 = root + "DOP3_" + op + ".bin";

    uint64_t prog_total = full_b * 3;
    g_total_bytes = prog_total;
    g_total_blocks = num_full;

    std::string p_rem_dec = root + "ex_dec_" + op;
    split_input(stripped, p_raw, p_rem_dec, full_b, 0);

    uint32_t shift_enc = calc_shift(k2, k1, BLOCK_SIZE);
    uint32_t shift_dec = (BLOCK_SIZE - shift_enc) % BLOCK_SIZE;

    if (structure == 0) {
        do_s_stage(p_raw, p_op1, shift_dec, num_full, BLOCK_SIZE, 0,        prog_total, num_full, "S-1 - Stage 1/3");
        do_e_stage(p_op1, p_op2, k2, full_b, true,  full_b,   prog_total, num_full, "E-1(K2) - Stage 2/3");
        do_e_stage(p_op2, p_op3, k1, full_b, true,  full_b*2, prog_total, num_full, "E-1(K1) - Stage 3/3");
    } else if (structure == 1) {
        do_e_stage(p_raw, p_op1, k1, full_b, true,  0,        prog_total, num_full, "E-1(K1) - Stage 1/3");
        do_s_stage(p_op1, p_op2, shift_dec, num_full, BLOCK_SIZE, full_b,   prog_total, num_full, "S-1 - Stage 2/3");
        do_e_stage(p_op2, p_op3, k1, full_b, true,  full_b*2, prog_total, num_full, "E-1(K1) - Stage 3/3");
    } else {
        do_e_stage(p_raw, p_op1, k1, full_b, true,  0,        prog_total, num_full, "E-1(K1) - Stage 1/3");
        do_e_stage(p_op1, p_op2, k2, full_b, true,  full_b,   prog_total, num_full, "E-1(K2) - Stage 2/3");
        do_s_stage(p_op2, p_op3, shift_dec, num_full, BLOCK_SIZE, full_b*2, prog_total, num_full, "S-1 - Stage 3/3");
    }

    prog_set("Writing output...", prog_total, prog_total, num_full, num_full);

    {
        std::string tmp = out_path + ".tmp";
        std::ifstream src_f(p_op3, std::ios::binary);
        std::ofstream dst_f(tmp,   std::ios::binary);
        src_f.seekg(0, std::ios::end);
        uint64_t decoded_sz = src_f.tellg();
        uint64_t discard    = (rem_size > 0) ? (BLOCK_SIZE - rem_size) : 0;
        uint64_t write_sz   = decoded_sz - discard;
        src_f.seekg(0, std::ios::beg);
        std::vector<char> buf(IO_BUF);
        uint64_t left = write_sz;
        while (left > 0) {
            size_t want = (size_t)std::min((uint64_t)IO_BUF, left);
            src_f.read(buf.data(), want);
            dst_f.write(buf.data(), src_f.gcount());
            left -= src_f.gcount();
        }
        dst_f.flush(); dst_f.close(); src_f.close();
        safe_rename(tmp, out_path);
    }

    { auto t_end = std::chrono::steady_clock::now();
      double secs = std::chrono::duration<double>(t_end - t_start).count();
      double mbps = (secs > 0) ? (full_b / 1048576.0) / secs : 0.0;
      prog_finish(true, "Done!", mbps); }
    for (auto& p : {p_raw, p_op1, p_op2, p_op3, stripped}) silent_rm(p);
    return out_path;
}

// ─────────────────────────────────────────────
// PROBE SENTINEL  (identical to PC probe_mjjb_sentinel)
// ─────────────────────────────────────────────
static bool probe_mjjb_sentinel(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::vector<char> probe(SENT_PRE_LEN);
    f.read(probe.data(), SENT_PRE_LEN);
    if ((size_t)f.gcount() < SENT_PRE_LEN) return false;
    return memcmp(probe.data(), MJJB_SENT_PRE, SENT_PRE_LEN) == 0;
}

// ═══════════════════════════════════════════
// JNI EXPORTS
// ═══════════════════════════════════════════

static std::thread g_worker;

extern "C" {

// Start encode/decode in background thread
JNIEXPORT jstring JNICALL
Java_com_mjjbcipher_MjjbEngine_startProcess(
    JNIEnv* env, jobject,
    jstring jInPath, jstring jTempDir, jstring jOutPath,
    jstring jKey1, jstring jKey2,
    jstring jK1Base, jstring jK2Base,
    jint jStructure, jint jBlockSize, jstring jMode)
{
    auto jstr = [&](jstring s) -> std::string {
        if (!s) return "";
        const char* c = env->GetStringUTFChars(s, nullptr);
        std::string r(c);
        env->ReleaseStringUTFChars(s, c);
        return r;
    };

    std::string inPath    = jstr(jInPath);
    std::string tempDir   = jstr(jTempDir);
    std::string outPath   = jstr(jOutPath);
    std::string k1s       = jstr(jKey1);
    std::string k2s       = jstr(jKey2);
    std::string k1base    = jstr(jK1Base);
    std::string k2base    = jstr(jK2Base);
    std::string mode      = jstr(jMode);
    int structure         = (int)jStructure;
    uint32_t BLOCK_SIZE   = (uint32_t)jBlockSize;

    if (BLOCK_SIZE < 57 || BLOCK_SIZE > 56789)
        return env->NewStringUTF("ERROR: invalid block size");
    if (k1s.empty() || k2s.empty())
        return env->NewStringUTF("ERROR: keys required");

    auto k1v = to_values(k1s, k1base);
    auto k2v = to_values(k2s, k2base);

    bool do_enc;
    if (mode == "encode") do_enc = true;
    else if (mode == "decode") do_enc = false;
    else do_enc = !probe_mjjb_sentinel(inPath);

    std::string outName = make_output_name(
        inPath.substr(inPath.rfind('/') + 1), do_enc);
    std::string finalOut = outPath + "/" + outName;

    if (g_worker.joinable()) g_worker.detach();

    g_running = true; g_finished = false; g_has_error = false;
    g_percent = 0; g_done_bytes = 0; g_total_bytes = 0;

    g_worker = std::thread([=]() {
        try {
            if (do_enc) run_encode(inPath, tempDir, finalOut, k1v, k2v, structure, BLOCK_SIZE);
            else        run_decode(inPath, tempDir, finalOut, k1v, k2v, structure, BLOCK_SIZE);
        } catch (std::exception& e) {
            prog_finish(false, (std::string("ERROR: ") + e.what()).c_str(), 0.0);
        }
    });
    return env->NewStringUTF(outName.c_str());
}
// Poll progress — returns JSON string (same fields as PC /progress endpoint)
JNIEXPORT jstring JNICALL
Java_com_mjjbcipher_MjjbEngine_getProgress(JNIEnv* env, jobject)
{
    char json[768];
    snprintf(json, sizeof(json),
        "{\"running\":%s,\"finished\":%s,\"has_error\":%s,"
        "\"percent\":%.2f,\"done_blocks\":%llu,\"total_blocks\":%llu,"
        "\"done_bytes\":%llu,\"total_bytes\":%llu,"
        "\"mbps\":%.2f,\"status\":\"%s\"}",
        g_running  ? "true" : "false",
        g_finished ? "true" : "false",
        g_has_error? "true" : "false",
        g_percent,
        (unsigned long long)g_done_blocks,
        (unsigned long long)g_total_blocks,
        (unsigned long long)g_done_bytes,
        (unsigned long long)g_total_bytes,
        g_mbps,
        g_status);
    return env->NewStringUTF(json);
}
// Probe file for MJJB sentinel — for auto-detect from JS
JNIEXPORT jboolean JNICALL
Java_com_mjjbcipher_MjjbEngine_probeIsMjjb(JNIEnv* env, jobject, jstring jPath)
{
    const char* c = env->GetStringUTFChars(jPath, nullptr);
    bool result = probe_mjjb_sentinel(std::string(c));
    env->ReleaseStringUTFChars(jPath, c);
    return (jboolean)result;
}
// make_output_name exposed for JS to show expected output filename
JNIEXPORT jstring JNICALL
Java_com_mjjbcipher_MjjbEngine_makeOutputName(JNIEnv* env, jobject,
    jstring jFname, jboolean doEnc)
{
    const char* c = env->GetStringUTFChars(jFname, nullptr);
    std::string result = make_output_name(std::string(c), (bool)doEnc);
    env->ReleaseStringUTFChars(jFname, c);
    return env->NewStringUTF(result.c_str());
}
  //  ===========  11-6-2026  CLAUDE 
  //  ===========  5-6-2026  CLAUDE 
} // extern "C"
