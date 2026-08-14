/* ==========================================================================
   MISIPULSA - CORE SYSTEM LOGIC & SUPABASE AUTH INTEGRATION (sistem.js)
   ==========================================================================
   CATATAN KEAMANAN (per 2026-08-14):
   - Status admin HANYA berasal dari kolom `is_admin` di tabel Supabase
     `profiles`. Tidak pernah disimpan / dipercaya dari localStorage.
   - Poin misi disinkronkan ke server melalui RPC `record_mission_claim`
     (SECURITY DEFINER) yang memvalidasi klaim di sisi server. Angka dari
     client TIDAK dipercaya sebagai sumber kebenaran.
   - Semua data yang dirender ke innerHTML di-escape lewat esc() untuk
     mencegah stored XSS.
   - Saat SUPABASE_URL / SUPABASE_ANON_KEY belum diisi, login/registrasi
     TIDAK dianggap berhasil (tidak ada mode demo diam-diam).
   ========================================================================== */

// ==================== SUPABASE CONFIGURATION ====================
// Masukkan Kredensial Dashboard Supabase Anda di Sini:
// Kredensial dibaca dari config.js (dihasilkan dari .env oleh generate-config.js).
// Selama kosong, app tetap jalan mode demo (login/registrasi ditolak dengan jelas).
const MISIPULSA_CONFIG = (typeof window !== 'undefined' && window.MISIPULSA_CONFIG) || {};
const SUPABASE_URL = MISIPULSA_CONFIG.supabaseUrl || 'YOUR_SUPABASE_URL'; // Contoh: https://xyzproject.supabase.co
const SUPABASE_ANON_KEY = MISIPULSA_CONFIG.supabaseAnonKey || 'YOUR_SUPABASE_ANON_KEY';

let supabaseClient = null;

function isSupabaseConfigured() {
    return supabaseClient !== null;
}

function initSupabase() {
    const urlOk = typeof SUPABASE_URL === 'string' &&
                  SUPABASE_URL.startsWith('http') &&
                  !SUPABASE_URL.includes('YOUR_');
    const keyOk = typeof SUPABASE_ANON_KEY === 'string' &&
                  SUPABASE_ANON_KEY.length > 20 &&
                  !SUPABASE_ANON_KEY.includes('YOUR_');

    if (typeof supabase !== 'undefined' && urlOk && keyOk) {
        try {
            supabaseClient = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
                auth: {
                    persistSession: true,
                    autoRefreshToken: true,
                    detectSessionInUrl: true,
                    flowType: 'pkce'
                }
            });
            console.log('Supabase client berhasil diinisialisasi.');
            return true;
        } catch (e) {
            console.warn('Supabase init warning:', e);
        }
    }
    supabaseClient = null;
    return false;
}

// Pastikan Supabase terkonfigurasi; jika tidak, beri tahu dengan jelas
// (TIDAK ada fallback login simulasi yang diam-diam).
function requireSupabase() {
    if (!initSupabase()) {
        showToast('⚠️ Supabase belum dikonfigurasi. Isi SUPABASE_URL & SUPABASE_ANON_KEY di sistem.js terlebih dahulu.', 'error');
        return false;
    }
    return true;
}

// ==================== HTML ESCAPING (ANTI-XSS) ====================
function esc(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Hanya izinkan link absolut http/https (cegah javascript: URL, skema lain,
// dan link relatif dari input/data DB)
function safeExternalLink(url) {
    if (!url) return '#';
    if (!/^https?:\/\//i.test(String(url))) return '#';
    try {
        const u = new URL(url);
        if (u.protocol === 'http:' || u.protocol === 'https:') return url;
    } catch (e) { /* invalid URL */ }
    return '#';
}

// ==================== SUPABASE AUTH FUNCTIONS ====================
async function signUpSupabase(email, password, userMetadata = {}) {
    if (!requireSupabase()) {
        return { success: false, error: 'Supabase belum dikonfigurasi' };
    }

    try {
        const { data, error } = await supabaseClient.auth.signUp({
            email: email,
            password: password,
            options: {
                data: {
                    full_name: userMetadata.full_name || 'Member MisiPulsa',
                    phone: userMetadata.phone || '',
                    referral_code: userMetadata.referral_code || ''
                }
            }
        });

        if (error) {
            showToast(`⚠️ Registrasi Gagal: ${error.message}`, 'error');
            return { success: false, error: error.message };
        }

        if (data.user && data.session) {
            currentUser = {
                id: data.user.id,
                name: userMetadata.full_name || 'Member Baru',
                email: email,
                phone: userMetadata.phone || '',
                totalEarned: 100,
                streak: 1,
                referralCode: 'MISI' + Math.floor(1000 + Math.random() * 9000),
                isAdmin: false
            };
            userPoints = 100;
            saveData();
            return { success: true, user: data.user };
        }

        if (data.user) {
            // Email confirmation wajib: akun dibuat tapi belum aktif
            showToast('📧 Akun dibuat. Silakan cek email untuk konfirmasi pendaftaran.', 'info');
            return { success: false, error: 'Email confirmation required' };
        }

        showToast('⚠️ Registrasi Gagal: respons tidak valid dari server.', 'error');
        return { success: false, error: 'Invalid server response' };
    } catch (err) {
        showToast(`⚠️ Error: ${err.message}`, 'error');
        return { success: false, error: err.message };
    }
}

async function signInSupabase(email, password) {
    if (!requireSupabase()) {
        return { success: false, error: 'Supabase belum dikonfigurasi' };
    }

    try {
        const { data, error } = await supabaseClient.auth.signInWithPassword({
            email: email,
            password: password
        });

        if (error) {
            showToast(`⚠️ Login Gagal: ${error.message}`, 'error');
            return { success: false, error: error.message };
        }

        if (data.user) {
            await fetchUserProfileSupabase(data.user.id, data.user.email);
            isLoggedIn = true;
            return { success: true, user: data.user };
        }
    } catch (err) {
        showToast(`⚠️ Error: ${err.message}`, 'error');
        return { success: false, error: err.message };
    }
}

async function fetchUserProfileSupabase(userId, email) {
    if (!supabaseClient) return;
    try {
        const { data, error } = await supabaseClient
            .from('profiles')
            .select('*')
            .eq('id', userId)
            .single();

        if (error) {
            console.warn('Profile fetch error:', error.message);
            return;
        }

        if (data) {
            currentUser = {
                id: data.id,
                name: data.full_name || 'Member MisiPulsa',
                email: email,
                phone: data.phone || '',
                totalEarned: data.points || 100,
                streak: data.streak || 1,
                referralCode: data.referral_code || 'MISI' + Math.floor(1000 + Math.random() * 9000),
                isAdmin: data.is_admin === true  // HANYA dari database, tidak pernah dari localStorage
            };
            userPoints = data.points || 100;
            saveData();
        }
    } catch (e) {
        console.warn('Profile fetch error:', e);
    }
}

async function signOutSupabase() {
    if (supabaseClient) {
        try { await supabaseClient.auth.signOut(); } catch (e) { console.warn('Sign out error:', e); }
    }
    logout();
}

async function resetPasswordSupabase(email) {
    if (!requireSupabase()) {
        return { success: false, error: 'Supabase belum dikonfigurasi' };
    }

    try {
        const { error } = await supabaseClient.auth.resetPasswordForEmail(email, {
            redirectTo: window.location.origin + '/reset-password.html',
        });
        if (error) {
            showToast(`⚠️ Reset Error: ${error.message}`, 'error');
            return { success: false, error: error.message };
        }
        showToast('✅ Link reset password berhasil dikirim ke email Anda!', 'success');
        return { success: true };
    } catch (err) {
        showToast(`⚠️ Error: ${err.message}`, 'error');
        return { success: false, error: err.message };
    }
}

async function checkSupabaseSession() {
    if (!supabaseClient) return;
    try {
        const { data: { session }, error } = await supabaseClient.auth.getSession();
        if (error) {
            console.warn('Session check error:', error.message);
            isLoggedIn = false;
            return;
        }
        if (session && session.user) {
            await fetchUserProfileSupabase(session.user.id, session.user.email);
            isLoggedIn = true;
        } else {
            isLoggedIn = false;
        }
    } catch (e) {
        console.warn('Session check failed:', e);
        isLoggedIn = false;
    }
}

// ==================== SERVER-DRIVEN DATA (SUPABASE) ====================
// Saat Supabase aktif, data misi & penarikan bersumber dari database,
// bukan localStorage. Mode demo (tanpa konfigurasi) tetap memakai state lokal.

function mapServerMission(m) {
    return {
        id: m.id,
        type: m.type || 'youtube',
        name: m.name || 'Misi',
        desc: m.desc_text || '',
        points: typeof m.points === 'number' ? m.points : 0,
        link: m.link,
        isYoutube: m.type === 'youtube',
        isMonetag: m.type === 'monetag',
        dailyLimit: m.type === 'daily',
        videoUrl: (m.type === 'youtube' && m.link) ? m.link : undefined
    };
}

function mapServerWithdrawal(w) {
    return {
        id: w.id,
        amount: w.amount || '',
        points: w.points || 0,
        date: w.created_at ? new Date(w.created_at).toLocaleDateString() : '',
        status: w.status || 'pending',
        method: w.method || '',
        user_name: w.user_name || ''
    };
}

// Muat daftar bank manual dari tabel `banks` (SELECT publik).
async function loadBanksFromServer() {
    if (!supabaseClient) return;
    try {
        const { data, error } = await supabaseClient
            .from('banks')
            .select('*')
            .order('id', { ascending: true });
        if (error) {
            console.warn('Load banks error:', error.message);
            return;
        }
        if (Array.isArray(data)) banks = data;
    } catch (e) {
        console.warn('Load banks failed:', e);
    }
}

// Muat daftar misi dari tabel `missions` (SELECT publik, admin & member).
async function loadMissionsFromServer() {
    if (!supabaseClient) return;
    try {
        const { data, error } = await supabaseClient
            .from('missions')
            .select('*')
            .order('id', { ascending: true });
        if (error) {
            console.warn('Load missions error:', error.message);
            return;
        }
        if (Array.isArray(data) && data.length > 0) {
            missions = data.map(mapServerMission);
            saveData();
        }
    } catch (e) {
        console.warn('Load missions failed:', e);
    }
}

// Muat riwayat penarikan milik user dari tabel `withdrawals` (policy: milik sendiri).
async function fetchMyWithdrawals() {
    if (!supabaseClient || !currentUser || !currentUser.id) return;
    try {
        const { data, error } = await supabaseClient
            .from('withdrawals')
            .select('*')
            .order('created_at', { ascending: false });
        if (error) {
            console.warn('Load withdrawals error:', error.message);
            return;
        }
        if (Array.isArray(data)) {
            withdrawHistory = data.map(mapServerWithdrawal);
            saveData();
        }
    } catch (e) {
        console.warn('Load withdrawals failed:', e);
    }
}

// Muat semua misi + semua penarikan untuk panel admin (policy admin).
async function loadAdminDataFromServer() {
    if (!supabaseClient) return;
    try {
        const [missionsRes, withdrawalsRes, depositsRes, banksRes] = await Promise.all([
            supabaseClient.from('missions').select('*').order('id', { ascending: true }),
            supabaseClient.from('withdrawals').select('*').order('created_at', { ascending: false }),
            supabaseClient.from('deposits').select('*').order('created_at', { ascending: false }),
            supabaseClient.from('banks').select('*').order('id', { ascending: true })
        ]);
        if (missionsRes.error) {
            console.warn('Load missions error:', missionsRes.error.message);
        } else if (Array.isArray(missionsRes.data) && missionsRes.data.length > 0) {
            missions = missionsRes.data.map(mapServerMission);
        }
        if (withdrawalsRes.error) {
            console.warn('Load withdrawals error:', withdrawalsRes.error.message);
        } else if (Array.isArray(withdrawalsRes.data)) {
            withdrawRequests = withdrawalsRes.data.map(mapServerWithdrawal);
        }
        if (depositsRes.error) {
            console.warn('Load deposits error:', depositsRes.error.message);
        } else if (Array.isArray(depositsRes.data)) {
            deposits = depositsRes.data;
        }
        if (banksRes.error) {
            console.warn('Load banks error:', banksRes.error.message);
        } else if (Array.isArray(banksRes.data)) {
            banks = banksRes.data;
        }

        // Statistik dihitung dari data yang baru dimuat (bukan hardcoded)
        recomputeAdminStats();

        // Total user: count baris profiles (policy admin: bisa lihat semua)
        const { count, error: countError } = await supabaseClient
            .from('profiles')
            .select('id', { count: 'exact', head: true });
        if (countError) {
            console.warn('Count users error:', countError.message);
            adminStats.totalUsers = null;
        } else {
            adminStats.totalUsers = typeof count === 'number' ? count : null;
        }

        saveData();
    } catch (e) {
        console.warn('Admin data load failed:', e);
    }
}

// Muat deposit milik member (riwayat transfer manual). Saat ada deposit
// berstatus approved dengan paket (note), upgrade lokal diaktifkan otomatis.
async function fetchMyDeposits() {
    if (!supabaseClient || !currentUser || !currentUser.id) return;
    try {
        const { data, error } = await supabaseClient
            .from('deposits')
            .select('*')
            .order('created_at', { ascending: false });
        if (error) {
            console.warn('Load deposits error:', error.message);
            return;
        }
        if (Array.isArray(data)) {
            myDeposits = data;
            myDeposits.forEach(d => {
                if (d.status === 'approved' && d.note) {
                    if (d.note.includes('Premium')) { isPremium = true; youtubeUpgraded = true; adUpgraded = true; }
                    else if (d.note.includes('YouTube')) youtubeUpgraded = true;
                    else if (d.note.includes('Ads')) adUpgraded = true;
                }
            });
            saveData();
        }
    } catch (e) {
        console.warn('Load deposits failed:', e);
    }
}

// Dipanggil dashboard.html setelah sesi dipastikan ada.
async function bootDashboard() {
    if (supabaseClient && currentUser && currentUser.id) {
        await Promise.all([loadMissionsFromServer(), fetchMyWithdrawals(), fetchMyDeposits(), loadBanksFromServer()]);
    }
    renderApp();
}

// Statistik panel admin (dihitung dari Supabase; fallback state lokal di demo)
let adminStats = { totalUsers: null, approvedPoints: 0, pendingWithdraw: 0 };

// Tab aktif panel admin (bottom nav) & sub-tab Transaksi
let adminActiveTab = 'stats';
let adminActiveTxTab = 'wd';

// Daftar user untuk tab User (diisi dari profiles saat Supabase aktif)
let adminUsers = [];

// Form inline admin: id yang sedang diedit (null = mode tambah) & tampil/tutup
let adminEditingMissionId = null;
let adminEditingUserId = null;
let adminEditingWdId = null;
let adminEditingDepoId = null;
let adminEditingBankId = null;
let adminShowUserForm = false;
let adminShowWdForm = false;
let adminShowDepoForm = false;
let adminShowBankForm = false;

// Hitung ulang statistik penarikan dari state yang sedang dimuat.
function recomputeAdminStats() {
    adminStats.pendingWithdraw = withdrawRequests.filter(w => (w.status || 'pending') === 'pending').length;
    adminStats.approvedPoints = withdrawRequests
        .filter(w => w.status === 'approved')
        .reduce((sum, w) => sum + (w.points || 0), 0);
}

// Muat daftar user dari tabel `profiles` untuk tab User (policy admin).
// Catatan: email ada di auth.users (tidak bisa di-select dengan anon key),
// jadi ditampilkan nomor HP / nama.
async function loadAdminUsersFromServer() {
    if (!supabaseClient) return;
    try {
        const { data, error } = await supabaseClient
            .from('profiles')
            .select('id, full_name, phone, points, level, is_admin, created_at')
            .order('created_at', { ascending: false });
        if (error) {
            console.warn('Load users error:', error.message);
            return;
        }
        if (Array.isArray(data)) adminUsers = data;
    } catch (e) {
        console.warn('Load users failed:', e);
    }
}

// Dipanggil admin.html setelah guard admin lolos.
async function openAdminPanel() {
    // Reset statistik & tab tiap kali panel dibuka
    adminStats = { totalUsers: null, approvedPoints: 0, pendingWithdraw: 0 };
    adminActiveTab = 'stats';
    adminActiveTxTab = 'wd';

    if (supabaseClient) {
        await loadAdminDataFromServer();
        await loadAdminUsersFromServer();
    } else {
        // Mode demo: statistik dihitung dari state lokal
        adminStats.pendingWithdraw = withdrawRequests.filter(w => (w.status || 'pending') === 'pending').length;
        adminStats.approvedPoints = withdrawRequests
            .concat(withdrawHistory)
            .filter(w => w.status === 'approved')
            .reduce((sum, w) => sum + (w.points || 0), 0);

        // Data user contoh untuk mode demo (hanya seed bila belum ada di localStorage)
        if (adminUsers.length === 0) {
            adminUsers = [
                { id: 'USR-1', full_name: 'Budi Santoso', phone: '0812xxxx1122', points: 15250, level: 'Free', is_admin: false, referral_code: 'MISI1111', created_at: '10-08-2026' },
                { id: 'USR-2', full_name: 'Siti Rahma', phone: '0857xxxx3344', points: 8450, level: 'Free', is_admin: false, referral_code: 'MISI2222', created_at: '11-08-2026' },
                { id: 'USR-3', full_name: 'Andi Wijaya', phone: '0896xxxx5566', points: 3200, level: 'Free', is_admin: false, referral_code: 'MISI3333', created_at: '12-08-2026' }
            ];
        }
        if (currentUser) {
            adminUsers.unshift({
                id: 'USR-ADM',
                full_name: currentUser.name,
                phone: currentUser.phone || '',
                points: userPoints,
                level: isPremium ? 'Premium' : (youtubeUpgraded || adUpgraded ? 'Upgrade' : 'Free'),
                is_admin: true,
                referral_code: currentUser.referralCode || '',
                created_at: '01-08-2026'
            });
        }
        adminStats.totalUsers = adminUsers.length;
    }
    renderAdminPanel();
}

// ==================== TOAST NOTIFICATION ====================
function showToast(message, type = 'info') {
    let toast = document.getElementById('toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast';
        toast.className = 'toast';
        document.body.appendChild(toast);
    }
    // Hapus emoji dari pesan agar tampil bersih & profesional (warna toast sudah cukup informatif)
    message = String(message)
        .replace(/[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}]/gu, '')
        .replace(/\s{2,}/g, ' ')
        .trim();
    toast.textContent = message;
    toast.className = `toast ${type}`;
    toast.classList.add('show');
    setTimeout(() => { toast.classList.remove('show'); }, 3000);
}

// ==================== MODAL LOGIN & AUTH ENGINE ====================
let generatedOtpModal = '123456';

function openLoginModal() {
    const modal = document.getElementById('loginModal');
    if (modal) {
        modal.classList.add('show');
        const loginForm = document.getElementById('loginFormModal');
        const otpForm = document.getElementById('otpFormModal');
        const antiCheat = document.getElementById('antiCheatWarningModal');
        if (loginForm) loginForm.style.display = 'block';
        if (otpForm) otpForm.style.display = 'none';
        if (antiCheat) antiCheat.classList.remove('show');
        generateOTPModal();
    } else {
        window.location.href = 'login.html';
    }
}

function closeLoginModal() {
    const modal = document.getElementById('loginModal');
    if (modal) modal.classList.remove('show');
}

document.addEventListener('click', function(e) {
    const modal = document.getElementById('loginModal');
    if (modal && e.target === modal) closeLoginModal();
});
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeLoginModal();
});

function generateOTPModal() {
    generatedOtpModal = Math.floor(100000 + Math.random() * 900000).toString();
    const demoCode = document.getElementById('demoOtpCodeModal');
    const otpDisp = document.getElementById('otpDisplayModal');
    if (demoCode) demoCode.textContent = generatedOtpModal;
    if (otpDisp) otpDisp.textContent = generatedOtpModal;
    return generatedOtpModal;
}

function sendOTPModal() {
    const phoneInput = document.getElementById('phoneInputModal');
    const phone = phoneInput ? phoneInput.value : '';
    if (!phone || phone.length < 8) {
        showToast('Masukkan nomor WhatsApp yang valid', 'error');
        return;
    }

    generateOTPModal();
    const btn = document.getElementById('sendOtpBtnModal');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Mengirim...';
    }

    setTimeout(() => {
        const loginForm = document.getElementById('loginFormModal');
        const otpForm = document.getElementById('otpFormModal');
        const otpInput = document.getElementById('otpInputModal');
        if (loginForm) loginForm.style.display = 'none';
        if (otpForm) otpForm.style.display = 'block';
        if (otpInput) otpInput.value = '';

        // Kode demo ditampilkan di layar (demoOtpCodeModal), TIDAK lewat toast
        showToast('✅ Kode OTP terkirim! Lihat kode demo di layar.', 'info');
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-paper-plane"></i> Kirim OTP';
        }
    }, 1200);
}

function backToLoginModal() {
    const loginForm = document.getElementById('loginFormModal');
    const otpForm = document.getElementById('otpFormModal');
    const otpInput = document.getElementById('otpInputModal');
    if (loginForm) loginForm.style.display = 'block';
    if (otpForm) otpForm.style.display = 'none';
    if (otpInput) otpInput.value = '';
}

function verifyOTPModal() {
    const otpInput = document.getElementById('otpInputModal');
    const otp = otpInput ? otpInput.value : '';
    if (!otp || otp.length < 4) {
        showToast('Masukkan kode OTP yang valid', 'error');
        return;
    }

    if (otp !== generatedOtpModal) {
        showToast('⚠️ Kode OTP salah, silakan coba lagi.', 'warning');
        return;
    }

    const btn = document.getElementById('verifyOtpBtnModal');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Memverifikasi...';
    }

    setTimeout(() => {
        performLogin();
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-check"></i> Verifikasi';
        }
        closeLoginModal();
    }, 1200);
}

function quickLoginModal() {
    showToast('🚀 Login cepat (Demo)...', 'info');
    setTimeout(() => {
        performLogin();
        closeLoginModal();
    }, 500);
}

// ==================== STATE UTAMA & DATA SEMENTARA ====================
let currentUser = null;
let userPoints = 0;
let isLoggedIn = false;
let currentTab = 'missions';

// LIMIT & UPGRADES
const FREE_LIMIT = 5;
const UPGRADE_LIMIT = 20;

let youtubeUpgraded = false;
let adUpgraded = false;
let isPremium = false;

let claimedMissions = new Set();
let dailyMissions = new Set();
let lastDailyDate = '';

let youtubeWatchCount = 0;
let adWatchCount = 0;

let activePlayerTimer = null;

// SAMPLE DATABASE MISI
let missions = [
    { id: 1, type: 'youtube', name: 'Nonton YouTube 15 Detik', desc: 'Tonton video YouTube singkat sampai selesai', points: 75, isYoutube: true, videoUrl: 'https://www.youtube.com/embed/dQw4w9WgXcQ' },
    { id: 2, type: 'monetag', name: 'Tonton Iklan Sponsor', desc: 'Selesaikan iklan singkat untuk klaim poin', points: 50, isMonetag: true },
    { id: 3, type: 'daily', name: 'Daily Check-in', desc: 'Klaim bonus login harian kamu setiap hari', points: 10, dailyLimit: true },
    { id: 4, type: 'sosmed', name: 'Follow Instagram @misipulsa', desc: 'Follow akun Instagram resmi kami', points: 30, link: 'https://instagram.com' },
    { id: 5, type: 'share', name: 'Bagikan ke WhatsApp', desc: 'Bagikan info MisiPulsa ke grup WA', points: 40, link: 'https://whatsapp.com' }
];

let withdrawHistory = [
    { id: 'WD-101', amount: 'Rp 10.000', points: 10000, date: '12-08-2026', status: 'completed', method: 'DANA' }
];

let activityHistory = [
    { id: 'ACT-1', title: 'Bonus Registrasi Baru', points: '+100', date: '12-08-2026 10:00', type: 'plus' }
];

// Riwayat deposit/upgrade (tab Transaksi > Depo di panel admin).
// Di Supabase, belum ada tabel payments — data ini lokal sampai payment
// provider sungguhan terhubung.
let upgradeRequests = [
    { id: 'UPG-101', user: 'Budi Santoso', type: 'YouTube VIP', amount: 'Rp 10.000', date: '11-08-2026', status: 'approved' },
    { id: 'UPG-102', user: 'Siti Rahma', type: 'Unlimited Premium', amount: 'Rp 25.000', date: '12-08-2026', status: 'pending' }
];
let withdrawRequests = [];

// Rekening bank manual (tujuan transfer member) & riwayat deposit.
// Supabase: dari tabel `banks` / `deposits`. Demo: localStorage.
let banks = [];
let deposits = [];
let myDeposits = []; // Deposit milik member (untuk riwayat transfer manual)

// Paket upgrade yang bisa dibeli lewat transfer manual
const MANUAL_PACKAGES = {
    'YouTube VIP': { price: 'Rp 10.000', points: 0 },
    'Ads VIP': { price: 'Rp 10.000', points: 0 },
    'Unlimited Premium': { price: 'Rp 25.000', points: 0 }
};

let downlineList = [
    { name: 'Budi Santoso', phone: '0812****1122', level: 1, date: '10-08-2026' },
    { name: 'Siti Rahma', phone: '0857****3344', level: 1, date: '11-08-2026' },
    { name: 'Andi Wijaya', phone: '0896****5566', level: 2, date: '12-08-2026' }
];

// ==================== INITIALIZE USER LOGGED IN ====================
function performLogin() {
    performLoginDemo('Member MisiPulsa', '08123456789');
}

// Demo login: status admin SELALU false. Admin hanya dari DB Supabase.
function performLoginDemo(name, phone) {
    const demoMode = !isSupabaseConfigured();
    currentUser = {
        name: name,
        phone: phone,
        referralCode: 'MISI' + Math.floor(1000 + Math.random() * 9000),
        totalEarned: 150,
        streak: 1,
        joinDate: '12-08-2026',
        isAdmin: false
    };

    userPoints = 150;
    isLoggedIn = true;

    saveData();
    if (demoMode) {
        showToast(`🎉 Selamat Datang (Mode Demo), ${name}! Supabase belum dikonfigurasi.`, 'info');
    } else {
        showToast(`🎉 Selamat Datang, ${name}!`, 'success');
    }

    if (window.location.pathname.includes('login.html') || window.location.pathname.includes('register.html')) {
        window.location.href = 'dashboard.html';
        return;
    }

    renderApp();
}

function logout() {
    currentUser = null;
    isLoggedIn = false;
    userPoints = 0;

    // Bersihkan SEMUA data lokal sesi
    const keys = [
        'mp_userPoints', 'mp_currentUser', 'mp_youtubeUpgraded', 'mp_adUpgraded', 'mp_isPremium',
        'mp_youtubeWatchCount', 'mp_adWatchCount', 'mp_claimedMissions', 'mp_dailyMissions',
        'mp_lastDailyDate', 'mp_activityHistory', 'mp_withdrawHistory',
        'mp_withdrawRequests', 'mp_upgradeRequests', 'mp_missions', 'mp_downlineList',
        'mp_banks', 'mp_adminUsers'
    ];
    keys.forEach(k => { try { localStorage.removeItem(k); } catch (e) { /* ignore */ } });

    showToast('👋 Anda telah keluar.', 'info');
    setTimeout(() => {
        window.location.href = 'login.html';
    }, 1000);
}

// ==================== LOCAL STORAGE PERSISTENCE ====================
function saveData() {
    try {
        localStorage.setItem('mp_userPoints', String(userPoints));
        // Status admin TIDAK pernah disimpan ke localStorage
        const safeUser = currentUser ? { ...currentUser } : null;
        if (safeUser) delete safeUser.isAdmin;
        localStorage.setItem('mp_currentUser', JSON.stringify(safeUser));
        localStorage.setItem('mp_youtubeUpgraded', String(youtubeUpgraded));
        localStorage.setItem('mp_adUpgraded', String(adUpgraded));
        localStorage.setItem('mp_isPremium', String(isPremium));
        localStorage.setItem('mp_youtubeWatchCount', String(youtubeWatchCount));
        localStorage.setItem('mp_adWatchCount', String(adWatchCount));
        localStorage.setItem('mp_claimedMissions', JSON.stringify([...claimedMissions]));
        localStorage.setItem('mp_dailyMissions', JSON.stringify([...dailyMissions]));
        localStorage.setItem('mp_lastDailyDate', lastDailyDate);
        localStorage.setItem('mp_activityHistory', JSON.stringify(activityHistory.slice(0, 100)));
        localStorage.setItem('mp_withdrawHistory', JSON.stringify(withdrawHistory));
        localStorage.setItem('mp_withdrawRequests', JSON.stringify(withdrawRequests));
        localStorage.setItem('mp_upgradeRequests', JSON.stringify(upgradeRequests));
        localStorage.setItem('mp_missions', JSON.stringify(missions));
        localStorage.setItem('mp_downlineList', JSON.stringify(downlineList));
        localStorage.setItem('mp_banks', JSON.stringify(banks));
        localStorage.setItem('mp_adminUsers', JSON.stringify(adminUsers));
    } catch (e) {
        console.warn('LocalStorage error:', e);
    }
}

function loadData() {
    try {
        const savedPoints = localStorage.getItem('mp_userPoints');
        if (savedPoints !== null) {
            const n = parseInt(savedPoints, 10);
            userPoints = Number.isFinite(n) ? n : 0;
        }

        const savedUser = localStorage.getItem('mp_currentUser');
        if (savedUser) {
            const u = JSON.parse(savedUser);
            if (u && typeof u === 'object') {
                currentUser = u;
                currentUser.isAdmin = false; // Jangan pernah percaya admin dari localStorage
            }
        }

        youtubeUpgraded = localStorage.getItem('mp_youtubeUpgraded') === 'true';
        adUpgraded = localStorage.getItem('mp_adUpgraded') === 'true';
        isPremium = localStorage.getItem('mp_isPremium') === 'true';

        youtubeWatchCount = parseInt(localStorage.getItem('mp_youtubeWatchCount') || '0', 10) || 0;
        adWatchCount = parseInt(localStorage.getItem('mp_adWatchCount') || '0', 10) || 0;

        claimedMissions = new Set(JSON.parse(localStorage.getItem('mp_claimedMissions') || '[]'));
        dailyMissions = new Set(JSON.parse(localStorage.getItem('mp_dailyMissions') || '[]'));
        lastDailyDate = localStorage.getItem('mp_lastDailyDate') || '';

        const arr = (key) => {
            const v = JSON.parse(localStorage.getItem(key) || '[]');
            return Array.isArray(v) ? v : [];
        };
        activityHistory = arr('mp_activityHistory');
        withdrawHistory = arr('mp_withdrawHistory');
        withdrawRequests = arr('mp_withdrawRequests');
        upgradeRequests = arr('mp_upgradeRequests');
        downlineList = arr('mp_downlineList');

        banks = arr('mp_banks');
        if (banks.length === 0) {
            banks = [
                { id: 1, bank_name: 'BCA', account_name: 'PT MisiPulsa', account_number: '1234567890', is_active: true },
                { id: 2, bank_name: 'DANA', account_name: 'MisiPulsa Official', account_number: '081234567890', is_active: true }
            ];
        }
        const savedAdminUsers = JSON.parse(localStorage.getItem('mp_adminUsers') || 'null');
        if (Array.isArray(savedAdminUsers) && savedAdminUsers.length > 0) adminUsers = savedAdminUsers;

        const savedMissions = JSON.parse(localStorage.getItem('mp_missions') || 'null');
        if (Array.isArray(savedMissions) && savedMissions.length > 0) missions = savedMissions;
    } catch (e) {
        console.warn('LocalStorage load error:', e);
    }
}

// ==================== RENDER APP & DASHBOARD TABS ====================
function renderApp() {
    const container = document.getElementById('mainApp');
    if (!container) return;

    container.innerHTML = `
        <!-- HEADER -->
        <div class="header">
            <div class="header-logo">
                <a href="index.html" class="logo-text" style="text-decoration:none;">
                    <span class="logo-icon"><i class="fas fa-mobile-screen-button"></i></span>
                    <span>MisiPulsa</span>
                </a>
            </div>

            <div id="pointsCardWrapper">
                <div class="points-card">
                    <div class="points-left">
                        <div class="points-label"><i class="fas fa-coins"></i> Total Poin</div>
                        <div class="points-value" id="userPoints">${(userPoints || 0).toLocaleString()}</div>
                    </div>
                    <div class="points-right">
                        <div class="points-level" id="userLevel">${isPremium ? '<i class="fas fa-crown"></i> Premium' : (youtubeUpgraded || adUpgraded ? '<i class="fas fa-rocket"></i> Upgrade' : '<i class="fas fa-user"></i> Free')}</div>
                        <div class="points-stats">
                            <span><i class="fas fa-chart-simple"></i> <strong id="totalEarned">${currentUser ? currentUser.totalEarned : 0}</strong></span>
                            <span><i class="fas fa-fire"></i> <strong id="streakCount">${currentUser ? currentUser.streak : 1}</strong></span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- MAIN CONTENT -->
        <div class="main-content" id="mainContent">

            <div class="tab-content active" id="tab-missions">
                <div id="missionsList"></div>
            </div>

            <div class="tab-content" id="tab-withdraw">
                <div class="page-title"><i class="fas fa-money-bill-transfer"></i> Tarik Poin</div>
                <p style="color:#888;font-size:13px;margin-bottom:12px;">
                    Minimal penarikan <strong>10.000 poin = Rp 10.000</strong>
                </p>
                <div class="withdraw-grid" id="withdrawGrid"></div>
                <h4 style="margin:16px 0 8px;font-size:14px;"><i class="fas fa-receipt"></i> Riwayat Penarikan</h4>
                <div id="withdrawHistory"></div>
            </div>

            <div class="tab-content" id="tab-upgrade">
                <div class="page-title"><i class="fas fa-crown"></i> Upgrade Account</div>
                <div id="upgradeList"></div>
            </div>

            <div class="tab-content" id="tab-referral">
                <div class="page-title"><i class="fas fa-users"></i> Program Referral</div>
                <div id="referralContent"></div>
            </div>

            <div class="tab-content" id="tab-account">
                <div class="page-title"><i class="fas fa-user"></i> Akun Saya</div>
                <div id="accountContent"></div>
            </div>

            <div class="tab-content" id="tab-history">
                <div class="page-title"><i class="fas fa-clock-rotate-left"></i> Riwayat Aktivitas</div>
                <div id="activityHistory"></div>
            </div>
        </div>

        <!-- BOTTOM NAV -->
        <div class="bottom-nav">
            <div class="nav-item active" data-tab="missions" onclick="switchTab('missions')">
                <i class="fas fa-home"></i><span>Beranda</span>
            </div>
            <div class="nav-item" data-tab="withdraw" onclick="switchTab('withdraw')">
                <i class="fas fa-wallet"></i><span>Tarik</span>
            </div>
            <div class="nav-item" data-tab="upgrade" onclick="switchTab('upgrade')">
                <i class="fas fa-star"></i><span>Upgrade</span>
            </div>
            <div class="nav-item" data-tab="referral" onclick="switchTab('referral')">
                <i class="fas fa-users"></i><span>Referral</span>
            </div>
            <div class="nav-item" data-tab="account" onclick="switchTab('account')">
                <i class="fas fa-user"></i><span>Akun</span>
            </div>
        </div>
    `;

    setTimeout(updateUI, 100);
}

function switchTab(tabName) {
    currentTab = tabName;
    const tabs = document.querySelectorAll('.tab-content');
    tabs.forEach(t => t.classList.remove('active'));

    const target = document.getElementById(`tab-${tabName}`);
    if (target) target.classList.add('active');

    const navItems = document.querySelectorAll('.bottom-nav .nav-item');
    navItems.forEach(n => {
        if (n.getAttribute('data-tab') === tabName) n.classList.add('active');
        else n.classList.remove('active');
    });

    // Kartu poin HANYA tampil di tab Beranda — tidak lengket di tab lain.
    const pointsWrap = document.getElementById('pointsCardWrapper');
    if (pointsWrap) pointsWrap.style.display = (tabName === 'missions') ? '' : 'none';

    updateUI();
}

function updateUI() {
    const userPointsEl = document.getElementById('userPoints');
    const totalEarned = document.getElementById('totalEarned');
    const streakCount = document.getElementById('streakCount');
    const userLevel = document.getElementById('userLevel');

    if (userPointsEl) userPointsEl.textContent = userPoints.toLocaleString();
    if (totalEarned && currentUser) totalEarned.textContent = currentUser.totalEarned.toLocaleString();
    if (streakCount && currentUser) streakCount.textContent = currentUser.streak;

    let levelText = '<i class="fas fa-user"></i> Free';
    if (isPremium) levelText = '<i class="fas fa-crown" style="color:#ffc107;"></i> Premium';
    else if (youtubeUpgraded || adUpgraded) levelText = '<i class="fas fa-rocket"></i> Upgrade';
    if (userLevel) userLevel.innerHTML = levelText;

    renderMissions();
    renderWithdrawOptions();
    renderUpgrades();
    renderHistory();
    renderWithdrawHistory();
    renderReferral();
    renderAccount();
}

// ==================== RENDER MISSIONS ENGINE ====================
function renderMissions() {
    const container = document.getElementById('missionsList');
    if (!container) return;

    const today = new Date().toISOString().split('T')[0];
    if (lastDailyDate !== today) {
        dailyMissions = new Set();
        lastDailyDate = today;
    }

    container.innerHTML = missions.map(m => {
        const isClaimed = claimedMissions.has(m.id);
        const isDaily = m.dailyLimit || false;
        const isDailyClaimed = dailyMissions.has(m.id);
        const maxCount = getMaxCount(m.type);
        const currentCount = getCurrentCount(m.type);
        const isLimitReached = currentCount >= maxCount;

        let limitText = '';
        if (m.isYoutube || m.isMonetag) {
            limitText = `${currentCount}/${maxCount}`;
        }

        let btnText = '<i class="fas fa-check"></i> Klaim';
        let btnClass = 'btn-claim';
        let disabled = false;
        let dailyBadge = '';

        if (isDaily && isDailyClaimed) {
            btnText = '<i class="fas fa-circle-check"></i> Selesai';
            btnClass += ' claimed';
            disabled = true;
            dailyBadge = '<span class="mission-daily-badge">Hari ini</span>';
        } else if (isClaimed && !m.isYoutube && !m.isMonetag) {
            btnText = '<i class="fas fa-circle-check"></i> Selesai';
            btnClass += ' claimed';
            disabled = true;
        }

        if ((m.isYoutube || m.isMonetag) && isLimitReached) {
            btnText = 'Limit Habis';
            btnClass += ' claimed';
            disabled = true;
        }

        if (m.isYoutube) {
            btnText = '<i class="fas fa-play"></i> Nonton';
            btnClass += ' youtube-btn';
        }

        if (m.isMonetag) {
            btnText = '<i class="fas fa-tv"></i> Tonton Iklan';
            btnClass += ' monetag-btn';
        }

        if (m.type === 'sosmed') {
            btnText = '<i class="fas fa-link"></i> Subscribe';
            btnClass += ' sosmed-btn';
        }

        if (m.type === 'share') {
            btnText = '<i class="fas fa-share"></i> Share';
            btnClass += ' share-btn';
        }

        return `
        <div class="mission-card">
            <div class="mission-icon ${esc(m.type)}">
                <i class="fas fa-${esc(getIconFa(m.type))}"></i>
            </div>
            <div class="mission-info">
                <h4>${esc(m.name)} ${dailyBadge}</h4>
                <p>${esc(m.desc)}</p>
                <div class="mission-footer">
                    <div>
                        <span class="mission-points">+${esc(m.points)} poin</span>
                        ${limitText ? `<span class="mission-limit"> • ${esc(limitText)}</span>` : ''}
                        ${isDaily ? '<span class="mission-daily-badge">1x/hari</span>' : ''}
                    </div>
                    <button class="${btnClass}"
                            onclick="handleMission(${esc(m.id)}, '${esc(m.type)}')"
                            ${disabled ? 'disabled' : ''}>
                        ${btnText}
                    </button>
                </div>
            </div>
        </div>
    `}).join('');
}

function getIconFa(type) {
    const icons = {
        'youtube': 'play-circle',
        'monetag': 'ad',
        'daily': 'calendar-day',
        'sosmed': 'share-alt',
        'share': 'share'
    };
    return icons[type] || 'star';
}

function getMaxCount(type) {
    if (type === 'youtube') return youtubeUpgraded ? UPGRADE_LIMIT : FREE_LIMIT;
    if (type === 'monetag') return adUpgraded ? UPGRADE_LIMIT : FREE_LIMIT;
    return 999;
}

function getCurrentCount(type) {
    if (type === 'youtube') return youtubeWatchCount;
    if (type === 'monetag') return adWatchCount;
    return 0;
}

function handleMission(missionId, type) {
    if (type === 'youtube') startYoutubeMission(missionId);
    else if (type === 'monetag') startMonetagMission(missionId);
    else if (type === 'daily') claimDailyMission(missionId);
    else if (type === 'sosmed') claimSosmedMission(missionId);
    else if (type === 'share') claimShareMission(missionId);
}

// ==================== VIDEO & ADS PLAYER ENGINE ====================
function startYoutubeMission(missionId) {
    const m = missions.find(x => x.id === missionId);
    if (!m) return;

    if (youtubeWatchCount >= getMaxCount('youtube')) {
        showToast('⛔ Limit nonton YouTube harian Anda sudah habis. Silakan Upgrade VIP!', 'warning');
        return;
    }

    openPlayerModal('Nonton Video YouTube', safeExternalLink(m.videoUrl) || 'https://www.youtube.com/embed/dQw4w9WgXcQ', 15, () => {
        youtubeWatchCount++;
        addPoints(m.points, `Nonton YouTube: ${m.name}`, m.id);
        showToast(`🎉 Berhasil dapat +${m.points} Poin!`, 'success');
        updateUI();
    });
}

function startMonetagMission(missionId) {
    const m = missions.find(x => x.id === missionId);
    if (!m) return;

    if (adWatchCount >= getMaxCount('monetag')) {
        showToast('⛔ Limit tonton iklan harian Anda sudah habis. Silakan Upgrade VIP!', 'warning');
        return;
    }

    openPlayerModal('Tonton Iklan Monetag', null, 15, () => {
        adWatchCount++;
        addPoints(m.points, `Tonton Iklan Monetag`, m.id);
        showToast(`🎉 Berhasil dapat +${m.points} Poin!`, 'success');
        updateUI();
    });
}

function claimDailyMission(missionId) {
    const m = missions.find(x => x.id === missionId);
    if (!m) return;

    dailyMissions.add(missionId);
    addPoints(m.points, 'Bonus Daily Check-in', m.id);
    showToast(`🎉 Bonus Harian +${m.points} Poin diklaim!`, 'success');
    updateUI();
}

function claimSosmedMission(missionId) {
    const m = missions.find(x => x.id === missionId);
    if (!m) return;

    const link = safeExternalLink(m.link || 'https://instagram.com');
    if (link !== '#') window.open(link, '_blank');
    claimedMissions.add(missionId);
    addPoints(m.points, m.name, m.id);
    showToast(`🎉 Poin SOSMED +${m.points} ditambahkan!`, 'success');
    updateUI();
}

function claimShareMission(missionId) {
    const m = missions.find(x => x.id === missionId);
    if (!m) return;

    const shareText = encodeURIComponent('Bisa dapat pulsa gratis cuma nonton video di MisiPulsa! Yuk gabung sekarang!');
    const waLink = `https://api.whatsapp.com/send?text=${shareText}`;
    window.open(waLink, '_blank');
    claimedMissions.add(missionId);
    addPoints(m.points, 'Share Ke WhatsApp', m.id);
    showToast(`🎉 Poin Share +${m.points} diklaim!`, 'success');
    updateUI();
}

// Tambah poin; jika `missionId` diberikan dan Supabase aktif, klaim juga
// divalidasi & dicatat di server lewat RPC `record_mission_claim` sehingga
// poin di DB tidak bisa dimanipulasi langsung oleh client.
async function addPoints(pts, title, missionId) {
    userPoints += pts;
    if (currentUser) currentUser.totalEarned += pts;
    activityHistory.unshift({
        id: 'ACT-' + Date.now(),
        title: title,
        points: `+${pts}`,
        date: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        type: 'plus'
    });
    saveData();

    if (supabaseClient && currentUser && currentUser.id && missionId && pts > 0) {
        try {
            const { data, error } = await supabaseClient.rpc('record_mission_claim', {
                p_mission_id: missionId
            });
            if (error) {
                console.warn('Server claim ditolak:', error.message);
                showToast(`⚠️ ${error.message}`, 'warning');
            } else if (typeof data === 'number') {
                // Server adalah sumber kebenaran poin
                userPoints = data;
                if (currentUser) currentUser.totalEarned = data;
                saveData();
            }
        } catch (e) {
            console.warn('Server claim failed:', e);
        }
    }
}

// ==================== PLAYER MODAL TEMPLATE ====================
function openPlayerModal(title, iframeUrl, seconds, onComplete) {
    let playerModal = document.getElementById('playerModal');
    if (!playerModal) {
        playerModal = document.createElement('div');
        playerModal.id = 'playerModal';
        playerModal.className = 'qris-modal';
        document.body.appendChild(playerModal);
    }

    playerModal.innerHTML = `
        <div class="qris-box" style="max-width: 450px;">
            <h3 style="margin-bottom:10px;">${esc(title)}</h3>
            <div style="background:#000; border-radius:12px; height:220px; position:relative; overflow:hidden; display:flex; align-items:center; justify-content:center;">
                ${iframeUrl ? `<iframe src="${esc(iframeUrl)}?autoplay=1" style="width:100%;height:100%;border:none;" allow="autoplay; encrypted-media"></iframe>` :
                `<div style="text-align:center;color:white;padding:20px;">
                    <div style="font-size:44px;margin-bottom:10px;"><i class="fas fa-bullhorn"></i></div>
                    <div style="font-size:14px;">Iklan Monetag Sedang Tampil...</div>
                </div>`}
            </div>

            <div style="margin-top:15px;">
                <div style="font-size:12px;color:#667eea;font-weight:bold;margin-bottom:6px;">
                    ⏳ Sisa Waktu Tonton: <span id="timerCountdown">${seconds}</span> Detik
                </div>
                <div style="width:100%;background:#e0e0e0;height:8px;border-radius:4px;overflow:hidden;">
                    <div id="timerProgress" style="width:100%;height:100%;background:linear-gradient(90deg, #667eea, #764ba2);transition:width 1s linear;"></div>
                </div>
            </div>

            <button id="claimRewardBtn" class="btn-paid" style="width:100%;margin-top:15px;display:none;" onclick="finishPlayerReward()">
                <i class="fas fa-gift"></i> Klaim Poin Sekarang
            </button>
            <button class="btn-close-qris" style="width:100%;margin-top:8px;background:#999;" onclick="closePlayerModal()">
                Tutup / Batal
            </button>
        </div>
    `;

    playerModal.classList.add('show');

    let currentSec = seconds;
    const timerDisplay = document.getElementById('timerCountdown');
    const progressBar = document.getElementById('timerProgress');
    const claimBtn = document.getElementById('claimRewardBtn');

    if (activePlayerTimer) clearInterval(activePlayerTimer);

    activePlayerTimer = setInterval(() => {
        currentSec--;
        if (timerDisplay) timerDisplay.textContent = currentSec;
        if (progressBar) progressBar.style.width = `${(currentSec / seconds) * 100}%`;

        if (currentSec <= 0) {
            clearInterval(activePlayerTimer);
            if (claimBtn) claimBtn.style.display = 'block';
            showToast('✅ Misi selesai! Klik Klaim Poin.', 'success');
        }
    }, 1000);

    window._currentPlayerCallback = onComplete;
}

function finishPlayerReward() {
    if (window._currentPlayerCallback) {
        window._currentPlayerCallback();
        window._currentPlayerCallback = null;
    }
    closePlayerModal();
}

function closePlayerModal() {
    const modal = document.getElementById('playerModal');
    if (modal) modal.classList.remove('show');
    if (activePlayerTimer) clearInterval(activePlayerTimer);
}

// ==================== WITHDRAW ENGINE ====================
function renderWithdrawOptions() {
    const container = document.getElementById('withdrawGrid');
    if (!container) return;

    const options = [
        { amount: 'Rp 10.000', points: 10000 },
        { amount: 'Rp 25.000', points: 25000 },
        { amount: 'Rp 50.000', points: 50000 },
        { amount: 'Rp 100.000', points: 100000 }
    ];

    container.innerHTML = options.map(opt => `
        <div class="withdraw-btn" onclick="requestWithdraw(${esc(opt.points)}, '${esc(opt.amount)}')">
            <div class="amount">${esc(opt.amount)}</div>
            <div class="points">${esc(opt.points.toLocaleString())} Poin</div>
            <span class="badge ${userPoints >= opt.points ? '' : 'disabled'}">
                ${userPoints >= opt.points ? 'Tersedia' : 'Poin Kurang'}
            </span>
        </div>
    `).join('');
}

function requestWithdraw(pointsNeeded, amountStr) {
    if (userPoints < pointsNeeded) {
        showToast(`⚠️ Poin Anda tidak cukup! Butuh ${pointsNeeded.toLocaleString()} poin.`, 'error');
        return;
    }

    const method = prompt('Pilih Metode Penarikan (DANA / OVO / GoPay / ShopeePay / Pulsa):', 'DANA');
    if (!method || !method.trim()) return;
    const accountNo = prompt(`Masukkan Nomor HP / E-Wallet ${method}:`, currentUser ? currentUser.phone : '08123456789');
    if (!accountNo || !accountNo.trim()) return;
    if (accountNo.length > 50) {
        showToast('Nomor tujuan terlalu panjang, coba lagi.', 'error');
        return;
    }

    userPoints -= pointsNeeded;
    const newReq = {
        id: 'WD-' + Date.now(),
        amount: amountStr,
        points: pointsNeeded,
        date: new Date().toLocaleDateString(),
        status: 'pending',
        method: `${method} (${accountNo})`
    };

    withdrawHistory.unshift(newReq);
    withdrawRequests.unshift(newReq);

    // Simpan permintaan penarikan ke tabel `withdrawals` di Supabase
    // (policy insert: milik sendiri) agar terlihat oleh admin.
    if (supabaseClient && currentUser && currentUser.id) {
        supabaseClient
            .from('withdrawals')
            .insert({
                id: newReq.id,
                user_id: currentUser.id,
                amount: amountStr,
                points: pointsNeeded,
                method: `${method} (${accountNo})`,
                status: 'pending'
            })
            .then(({ error }) => {
                if (error) console.warn('Withdraw insert error:', error.message);
            })
            .catch((e) => console.warn('Withdraw insert failed:', e));
    }

    addPoints(0, `Penarikan ${amountStr} (${method})`);
    showToast(`✅ Permintaan penarikan ${amountStr} berhasil dikirim! Mohon tunggu konfirmasi admin.`, 'success');
    updateUI();
}

function renderWithdrawHistory() {
    const container = document.getElementById('withdrawHistory');
    if (!container) return;

    if (withdrawHistory.length === 0) {
        container.innerHTML = '<div style="color:#999;font-size:12px;text-align:center;padding:10px;">Belum ada riwayat penarikan.</div>';
        return;
    }

    container.innerHTML = withdrawHistory.map(w => `
        <div class="history-item">
            <div class="history-left">
                <div class="title">${esc(w.amount)} — ${esc(w.method)}</div>
                <div class="date">${esc(w.date)} • ID: ${esc(w.id)}</div>
            </div>
            <span class="status-badge ${esc(w.status)}">${esc(String(w.status || '').toUpperCase())}</span>
        </div>
    `).join('');
}

// ==================== UPGRADE & QRIS ENGINE ====================
function renderUpgrades() {
    const container = document.getElementById('upgradeList');
    if (!container) return;

    const activeBanks = banks.filter(b => b.is_active !== false);
    const myDeps = supabaseClient
        ? myDeposits
        : upgradeRequests.filter(r => r.user === (currentUser ? currentUser.name : ''));

    container.innerHTML = `
        <div class="upgrade-card">
            <div class="icon"><i class="fas fa-circle-play"></i></div>
            <span class="featured">BEST SELLER</span>
            <h4>Upgrade YouTube VIP</h4>
            <p>Buka limit nonton dari 5 video menjadi 20 video per hari (+1.500 Poin/hari)!</p>
            <div class="cost">
                Harga: <span class="price">Rp 10.000</span>
            </div>
            <button class="btn-upgrade ${youtubeUpgraded ? 'active-btn' : ''}"
                    onclick="openQRISModal('YouTube VIP', 'Rp 10.000')"
                    ${youtubeUpgraded ? 'disabled' : ''}>
                ${youtubeUpgraded ? '<i class="fas fa-circle-check"></i> Aktif' : '<i class="fas fa-bolt"></i> Upgrade Sekarang (QRIS)'}
            </button>
        </div>

        <div class="upgrade-card">
            <div class="icon"><i class="fas fa-tv"></i></div>
            <h4>Upgrade Ads VIP</h4>
            <p>Buka limit tonton iklan Monetag hingga 20 iklan per hari (+1.000 Poin/hari)!</p>
            <div class="cost">
                Harga: <span class="price">Rp 10.000</span>
            </div>
            <button class="btn-upgrade ${adUpgraded ? 'active-btn' : ''}"
                    onclick="openQRISModal('Ads VIP', 'Rp 10.000')"
                    ${adUpgraded ? 'disabled' : ''}>
                ${adUpgraded ? '<i class="fas fa-circle-check"></i> Aktif' : '<i class="fas fa-bolt"></i> Upgrade Sekarang (QRIS)'}
            </button>
        </div>

        <div class="upgrade-card">
            <div class="icon"><i class="fas fa-crown" style="color:#ffc107;"></i></div>
            <h4>Upgrade Unlimited Premium</h4>
            <p>Dapatkan semua akses VIP YouTube & Ads + Bonus 500 Poin Instan & Komisi 2x lipat!</p>
            <div class="cost">
                Harga: <span class="price">Rp 25.000</span>
            </div>
            <button class="btn-upgrade premium-btn ${isPremium ? 'active-btn' : ''}"
                    onclick="openQRISModal('Unlimited Premium', 'Rp 25.000')"
                    ${isPremium ? 'disabled' : ''}>
                ${isPremium ? '<i class="fas fa-circle-check"></i> Aktif' : '<i class="fas fa-fire"></i> Upgrade Premium (QRIS)'}
            </button>
        </div>

        <div class="upgrade-card">
            <div class="icon"><i class="fas fa-building-columns"></i></div>
            <h4>Transfer Manual (Bank)</h4>
            <p style="font-size:12px;color:#888;">Pilih paket, transfer ke rekening tujuan, lalu upload bukti transfer. Admin memverifikasi sebelum upgrade aktif.</p>

            <div class="manual-transfer-form">
                <label for="manualUpgradeType"><i class="fas fa-gem"></i> Pilih Paket Upgrade</label>
                <select id="manualUpgradeType">
                    ${Object.entries(MANUAL_PACKAGES).map(([name, p]) => `<option value="${esc(name)}">${esc(name)} — ${esc(p.price)}</option>`).join('')}
                </select>

                <label for="manualBankSelect"><i class="fas fa-building-columns"></i> Transfer ke Bank</label>
                <select id="manualBankSelect">
                    ${activeBanks.length === 0 ? '<option value="">Belum ada bank aktif</option>' :
                    activeBanks.map(b => `<option value="${esc(b.id)}">${esc(b.bank_name)} • ${esc(b.account_number)} (a.n. ${esc(b.account_name || '-')})</option>`).join('')}
                </select>

                <label for="manualProofInput"><i class="fas fa-image"></i> Upload Bukti Transfer (foto)</label>
                <input type="file" id="manualProofInput" accept="image/*" onchange="previewManualProof(event)">
                <img id="manualProofPreview" alt="Pratinjau bukti transfer">

                <button class="btn-paid" onclick="submitManualTransfer()">
                    <i class="fas fa-paper-plane"></i> Kirim Bukti Transfer
                </button>
            </div>

            <h4 style="margin:16px 0 8px;font-size:14px;"><i class="fas fa-receipt"></i> Riwayat Transfer Manual</h4>
            <div id="myDepositsList">
                ${myDeps.length === 0 ? '<p style="font-size:12px;color:#999;">Belum ada transfer manual.</p>' :
                myDeps.map(d => `
                    <div class="upgrade-request-item" style="border-left-color:#667eea;">
                        <div class="ur-info">
                            <span class="ur-type">${esc(d.note || d.type || d.method || 'Transfer')}</span>
                            <span class="ur-amount">${esc(d.amount)}</span>
                            <span class="ur-status ${esc(d.status || 'pending')}">${esc(String(d.status || 'pending').toUpperCase())}</span>
                        </div>
                        <div style="font-size:11px;color:#999;margin-top:4px;">${esc(d.method || '')} • ${esc(d.created_at ? new Date(d.created_at).toLocaleDateString() : (d.date || ''))}</div>
                    </div>`).join('')}
            </div>
        </div>
    `;
}

// Pratinjau bukti transfer yang dipilih member (tanpa upload)
function previewManualProof(event) {
    const file = event && event.target && event.target.files && event.target.files[0];
    const preview = document.getElementById('manualProofPreview');
    if (!file || !preview) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        preview.src = e.target.result;
        preview.style.display = 'block';
    };
    reader.readAsDataURL(file);
}

// Baca file gambar, kompres jadi JPEG data URL (maks ~640px, kualitas 0.65)
// agar muat disimpan di kolom TEXT Supabase.
function readImageProof(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => {
            const img = new Image();
            img.onload = () => {
                try {
                    const maxW = 640;
                    let width = img.width || 320;
                    let height = img.height || 240;
                    if (width > maxW) {
                        height = Math.round(height * maxW / width);
                        width = maxW;
                    }
                    const canvas = document.createElement('canvas');
                    canvas.width = width;
                    canvas.height = height;
                    canvas.getContext('2d').drawImage(img, 0, 0, width, height);
                    resolve(canvas.toDataURL('image/jpeg', 0.65));
                } catch (err) {
                    reject(err);
                }
            };
            img.onerror = () => reject(new Error('Gambar tidak bisa dibaca.'));
            img.src = e.target.result;
        };
        reader.onerror = () => reject(new Error('File tidak bisa dibaca.'));
        reader.readAsDataURL(file);
    });
}

// Kirim transfer manual: simpan ke tabel `deposits` (status pending + bukti).
async function submitManualTransfer() {
    if (!currentUser) {
        showToast('Silakan login terlebih dahulu.', 'warning');
        return;
    }
    const type = document.getElementById('manualUpgradeType')?.value;
    const bankId = document.getElementById('manualBankSelect')?.value;
    const fileInput = document.getElementById('manualProofInput');

    if (!type || !bankId) {
        showToast('Pilih paket upgrade dan bank tujuan terlebih dahulu.', 'warning');
        return;
    }
    if (!fileInput || !fileInput.files || !fileInput.files[0]) {
        showToast('Upload bukti transfer (foto) terlebih dahulu.', 'warning');
        return;
    }

    const bank = banks.find(b => String(b.id) === String(bankId));
    const pkg = MANUAL_PACKAGES[type] || { price: 'Rp 10.000' };

    showToast('Memproses bukti transfer...', 'info');
    let proof = null;
    try {
        proof = await readImageProof(fileInput.files[0]);
    } catch (e) {
        showToast(e.message || 'Gagal memproses gambar.', 'error');
        return;
    }

    const newDep = {
        id: 'DEP-' + Date.now(),
        user_id: currentUser.id || null,
        user_name: currentUser.name || 'Member',
        amount: pkg.price,
        points: pkg.points || 0,
        method: bank ? bank.bank_name : 'Transfer Bank',
        note: type,
        status: 'pending',
        proof_image: proof
    };

    if (supabaseClient) {
        try {
            const { error } = await supabaseClient.from('deposits').insert(newDep);
            if (error) {
                showToast(`Gagal mengirim: ${error.message}`, 'error');
                return;
            }
            myDeposits.unshift(newDep);
        } catch (e) {
            showToast(`Gagal mengirim: ${e.message}`, 'error');
            return;
        }
    } else {
        // Mode demo
        upgradeRequests.unshift({
            id: newDep.id,
            user: newDep.user_name,
            type: newDep.note,
            amount: newDep.amount,
            points: newDep.points,
            method: newDep.method,
            date: new Date().toLocaleDateString(),
            status: 'pending',
            proof_image: newDep.proof_image,
            note: newDep.note
        });
        saveData();
    }

    if (fileInput) fileInput.value = '';
    const preview = document.getElementById('manualProofPreview');
    if (preview) { preview.style.display = 'none'; preview.src = ''; }

    showToast('Bukti transfer terkirim. Menunggu konfirmasi admin.', 'success');
    renderUpgrades();
}

function copyBankNumber(accountNumber) {
    navigator.clipboard.writeText(String(accountNumber));
    showToast(`No. rekening disalin: ${accountNumber}`, 'success');
}

// ==================== ADMIN: LIHAT BUKTI TRANSFER ====================
function openProofModal(id) {
    const r = getDeposits().find(x => String(x.id) === String(id));
    if (!r) {
        showToast('Transaksi tidak ditemukan.', 'warning');
        return;
    }
    if (!r.proof_image) {
        showToast('Tidak ada bukti transfer untuk transaksi ini.', 'warning');
        return;
    }

    let modal = document.getElementById('proofModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'proofModal';
        modal.className = 'qris-modal';
        document.body.appendChild(modal);
    }

    modal.innerHTML = `
        <div class="qris-box" style="max-width:440px;">
            <h3><i class="fas fa-image"></i> Bukti Transfer</h3>
            <p style="font-size:12px;color:#888;margin-bottom:12px;">
                ${esc(r.user_name || r.user)} • ${esc(r.note || '')}${r.note ? ' • ' : ''}${esc(r.amount)} • ${esc(r.status || '')}
            </p>
            <img src="${esc(r.proof_image)}" alt="Bukti Transfer" style="width:100%;border-radius:12px;max-height:60vh;object-fit:contain;background:#f0f0f0;">
            <button class="btn-close-qris" style="width:100%;margin-top:12px;background:#667eea;" onclick="closeProofModal()">
                <i class="fas fa-xmark"></i> Tutup
            </button>
        </div>
    `;
    modal.classList.add('show');
}

function closeProofModal() {
    const modal = document.getElementById('proofModal');
    if (modal) modal.classList.remove('show');
}

let activeUpgradeTarget = null;

function openQRISModal(type, priceStr) {
    activeUpgradeTarget = { type, priceStr };
    const modal = document.getElementById('qrisModal');
    if (!modal) return;

    document.getElementById('qrisUpgradeType').textContent = type;
    document.getElementById('qrisAmount').textContent = priceStr;
    document.getElementById('qrisTransactionId').textContent = 'TRX-' + Math.floor(100000 + Math.random() * 900000);

    modal.classList.add('show');
    modal.style.display = 'flex';
}

function closeQRISModal() {
    const modal = document.getElementById('qrisModal');
    if (modal) {
        modal.classList.remove('show');
        modal.style.display = 'none';
    }
}

function confirmQRISPayment() {
    if (!activeUpgradeTarget) return;

    if (activeUpgradeTarget.type.includes('YouTube')) youtubeUpgraded = true;
    if (activeUpgradeTarget.type.includes('Ads')) adUpgraded = true;
    if (activeUpgradeTarget.type.includes('Premium')) {
        isPremium = true;
        youtubeUpgraded = true;
        adUpgraded = true;
        addPoints(500, 'Bonus Upgrade Premium');
    }

    // Catat transaksi deposit agar tampil di panel admin (Transaksi > Depo)
    upgradeRequests.unshift({
        id: 'UPG-' + Date.now(),
        user: currentUser ? currentUser.name : 'Member',
        type: activeUpgradeTarget.type,
        amount: activeUpgradeTarget.priceStr,
        date: new Date().toLocaleDateString(),
        status: 'approved'
    });

    // Saat Supabase aktif, catat juga ke tabel `deposits` agar admin melihatnya
    // dari server (bukan cuma state lokal).
    if (supabaseClient && currentUser && currentUser.id) {
        supabaseClient
            .from('deposits')
            .insert({
                id: 'DEP-' + Date.now(),
                user_id: currentUser.id,
                user_name: currentUser.name || 'Member',
                amount: activeUpgradeTarget.priceStr,
                points: 0,
                method: activeUpgradeTarget.type,
                status: 'approved'
            })
            .then(({ error }) => { if (error) console.warn('Deposit insert error:', error.message); })
            .catch((e) => console.warn('Deposit insert failed:', e));
    }

    saveData();
    closeQRISModal();
    showToast(`🎉 Upgrade ${activeUpgradeTarget.type} Berhasil Diaktifkan!`, 'success');
    updateUI();
}

// ==================== REFERRAL NETWORK ENGINE ====================
function renderReferral() {
    const container = document.getElementById('referralContent');
    if (!container) return;

    const refCode = currentUser ? currentUser.referralCode : 'MISI8899';
    const origin = (window.location.origin && window.location.origin !== 'null') ? window.location.origin : '';
    const refLink = `${origin}/register.html?ref=${encodeURIComponent(refCode)}`;

    container.innerHTML = `
        <div class="referral-card">
            <h4>Kode Referral Anda</h4>
            <p style="font-size:12px;color:#888;">Bagikan kode ini ke temanmu dan dapatkan <strong>+50 Poin</strong> setiap pendaftaran!</p>
            <div class="code-box" onclick="copyReferralCode('${esc(refCode)}')">${esc(refCode)}</div>

            <div class="referral-link-box">
                <span class="link-text">${esc(refLink)}</span>
                <button class="btn-copy-link" onclick="copyReferralLink('${esc(refLink)}')">Salin Link</button>
            </div>

            <div class="referral-stats">
                <div class="referral-stat">
                    <div class="number">${downlineList.length}</div>
                    <div class="label">Total Referral</div>
                </div>
                <div class="referral-stat">
                    <div class="number">+${downlineList.length * 50}</div>
                    <div class="label">Bonus Poin</div>
                </div>
                <div class="referral-stat">
                    <div class="number">3 Level</div>
                    <div class="label">Kedalaman</div>
                </div>
            </div>
        </div>

        <div class="referral-card">
            <div class="downline-header" onclick="toggleDownlineTree()">
                <span><i class="fas fa-sitemap"></i> Jaringan Downline (Pohon Referral)</span>
                <span class="arrow" id="downlineArrow">▼</span>
            </div>
            <div class="downline-content" id="downlineTreeContent">
                ${downlineList.map(d => `
                    <div class="downline-item">
                        <div>
                            <div class="name">${esc(d.name)} (${esc(d.phone)})</div>
                            <div class="date">Bergabung: ${esc(d.date)}</div>
                        </div>
                        <span class="badge-level l${esc(d.level)}">Level ${esc(d.level)}</span>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

function toggleDownlineTree() {
    const content = document.getElementById('downlineTreeContent');
    const arrow = document.getElementById('downlineArrow');
    if (content) content.classList.toggle('open');
    if (arrow) arrow.classList.toggle('open');
}

function copyReferralCode(code) {
    navigator.clipboard.writeText(code);
    showToast(`📋 Kode referral ${code} berhasil disalin!`, 'success');
}

function copyReferralLink(link) {
    navigator.clipboard.writeText(link);
    showToast('📋 Link referral berhasil disalin!', 'success');
}

// ==================== ACCOUNT & PROFILE ====================
function renderAccount() {
    const container = document.getElementById('accountContent');
    if (!container) return;

    container.innerHTML = `
        <div class="account-info">
            <div class="row">
                <span class="label">Nama Pengguna:</span>
                <span class="value">${esc(currentUser ? currentUser.name : 'Pengguna')}</span>
            </div>
            <div class="row">
                <span class="label">Email / WhatsApp:</span>
                <span class="value">${esc(currentUser ? (currentUser.email || currentUser.phone) : '-')}</span>
            </div>
            <div class="row">
                <span class="label">Status Akun:</span>
                <span class="value" style="color:#4caf50;">
                    ${isPremium ? '<i class="fas fa-crown"></i> VIP Premium' : (youtubeUpgraded || adUpgraded ? '<i class="fas fa-rocket"></i> Upgrade' : '<i class="fas fa-user"></i> Free Member')}
                </span>
            </div>
            <div class="row">
                <span class="label">Kode Referral:</span>
                <span class="value">${esc(currentUser ? currentUser.referralCode : '-')}</span>
            </div>
        </div>

        <div class="account-menu">
            ${currentUser && currentUser.isAdmin ? `
            <a href="admin.html" class="menu-item" style="text-decoration:none;color:inherit;">
                <span class="icon"><i class="fas fa-wrench"></i></span>
                <span class="text">Buka Admin Panel</span>
                <span class="arrow">›</span>
            </a>` : ''}
            <div class="menu-item" onclick="switchTab('history')">
                <span class="icon"><i class="fas fa-clock-rotate-left"></i></span>
                <span class="text">Riwayat Aktivitas Poin</span>
                <span class="arrow">›</span>
            </div>
            <div class="menu-item danger" onclick="signOutSupabase()">
                <span class="icon"><i class="fas fa-right-from-bracket"></i></span>
                <span class="text">Keluar Akun (Logout)</span>
                <span class="arrow">›</span>
            </div>
        </div>
    `;
}

function renderHistory() {
    const container = document.getElementById('activityHistory');
    if (!container) return;

    container.innerHTML = activityHistory.map(act => `
        <div class="history-item">
            <div class="history-left">
                <div class="title">${esc(act.title)}</div>
                <div class="date">${esc(act.date)}</div>
            </div>
            <span style="font-weight:bold;color:${act.type === 'plus' ? '#4caf50' : '#f44336'};">
                ${esc(act.points)}
            </span>
        </div>
    `).join('');
}

// ==================== ADMIN PANEL ENGINE ====================
function renderAdminPanel() {
    const container = document.getElementById('adminContent');
    if (!container) return;

    // Pengaman ganda: jangan render panel jika bukan admin
    if (!currentUser || !currentUser.isAdmin) {
        container.innerHTML = '<p style="color:#f44336;"><i class="fas fa-ban"></i> Akses ditolak.</p>';
        showToast('⛔ Akses ditolak: Anda bukan admin.', 'error');
        return;
    }

    // ---------- TAB: STATISTIK ----------
    const statsTab = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px;">
            <div class="admin-stat-card">
                <div class="admin-stat-label">Total User</div>
                <div class="admin-stat-value" style="color:#667eea;">${adminStats.totalUsers !== null ? adminStats.totalUsers.toLocaleString() : '—'}</div>
            </div>
            <div class="admin-stat-card">
                <div class="admin-stat-label">Total Penarikan Disetujui (Rp)</div>
                <div class="admin-stat-value" style="color:#4caf50;">Rp ${adminStats.approvedPoints.toLocaleString()}</div>
            </div>
            <div class="admin-stat-card">
                <div class="admin-stat-label">Antrean Penarikan (Pending)</div>
                <div class="admin-stat-value" style="color:#ff9800;">${adminStats.pendingWithdraw}</div>
            </div>
            <div class="admin-stat-card">
                <div class="admin-stat-label">Total Misi Aktif</div>
                <div class="admin-stat-value" style="color:#e91e63;">${missions.length}</div>
            </div>
        </div>

        <div class="admin-section">
            <h4><i class="fas fa-money-bill-wave"></i> Penarikan Terbaru</h4>
            ${withdrawRequests.length === 0 ? '<p style="font-size:12px;color:#888;">Belum ada penarikan.</p>' :
            withdrawRequests.slice(0, 5).map(w => `
                <div class="wd-request-item">
                    <div class="wd-info">
                        <span class="wd-user">${esc(w.method)}</span>
                        <span class="wd-amount">${esc(w.amount)}</span>
                        <span class="status-badge ${esc(w.status || 'pending')}">${esc(String(w.status || 'pending').toUpperCase())}</span>
                    </div>
                </div>`).join('')}
        </div>
    `;

    // ---------- TAB: TRANSAKSI (WD / DEPO) ----------
    const depoList = getDeposits();
    const txTab = `
        <div class="admin-tx-tabs">
            <button type="button" class="admin-tx-tab ${adminActiveTxTab === 'wd' ? 'active' : ''}" data-txtab="wd" onclick="switchAdminTxTab('wd')"><i class="fas fa-money-bill-wave"></i> Penarikan (WD)</button>
            <button type="button" class="admin-tx-tab ${adminActiveTxTab === 'depo' ? 'active' : ''}" data-txtab="depo" onclick="switchAdminTxTab('depo')"><i class="fas fa-building-columns"></i> Deposit / Upgrade</button>
        </div>

        <div id="adminTxWd" class="admin-section ${adminActiveTxTab === 'wd' ? '' : 'admin-hidden'}">
            <h4><i class="fas fa-money-bill-wave"></i> Persetujuan Penarikan</h4>
            <button class="btn-add" onclick="toggleAdminWdForm()">${adminShowWdForm ? '— Tutup Form' : '+ Tambah WD Manual'}</button>
            ${adminShowWdForm ? `
            <div class="admin-form">
                <div class="form-row">
                    <input type="text" id="adminWdUserName" placeholder="Nama User (untuk WD manual)" maxlength="60">
                    <select id="adminWdStatus">
                        <option value="pending">Pending</option>
                        <option value="approved">Disetujui</option>
                        <option value="rejected">Ditolak</option>
                    </select>
                </div>
                <div class="form-row">
                    <input type="number" id="adminWdPoints" placeholder="Nominal (Rp / poin)" min="1000" step="1000">
                    <input type="text" id="adminWdMethod" placeholder="Metode (DANA / OVO / GoPay...)" maxlength="60">
                </div>
                <div class="form-actions">
                    <button class="btn-add" onclick="saveWdAdmin()"><i class="fas fa-floppy-disk"></i> ${adminEditingWdId ? 'Simpan Perubahan' : 'Simpan WD'}</button>
                    <button class="btn-outline" onclick="cancelWdEdit()">Batal</button>
                </div>
            </div>` : ''}
            ${withdrawRequests.length === 0 ? '<p style="font-size:12px;color:#888;">Tidak ada data penarikan.</p>' :
            withdrawRequests.map(w => {
                const isPending = (w.status || 'pending') === 'pending';
                return `
                <div class="wd-request-item">
                    <div class="wd-info">
                        <span class="wd-user">${esc(w.user_name || w.method)}</span>
                        <span class="wd-amount">${esc(w.amount)}</span>
                        <span class="status-badge ${esc(w.status || 'pending')}">${esc(String(w.status || 'pending').toUpperCase())}</span>
                    </div>
                    <div class="wd-actions">
                        ${isPending ? `
                        <button class="btn-approve" onclick="approveWithdrawAdmin('${esc(w.id)}')"><i class="fas fa-circle-check"></i> Setujui</button>
                        <button class="btn-reject" onclick="rejectWithdrawAdmin('${esc(w.id)}')"><i class="fas fa-circle-xmark"></i> Tolak</button>` : ''}
                        <button class="btn-edit" onclick="editWdAdmin('${esc(w.id)}')"><i class="fas fa-pen"></i></button>
                        <button class="btn-delete-mission" onclick="deleteWdAdmin('${esc(w.id)}')"><i class="fas fa-trash-can"></i></button>
                    </div>
                </div>`;
            }).join('')}
        </div>

        <div id="adminTxDepo" class="admin-section ${adminActiveTxTab === 'depo' ? '' : 'admin-hidden'}">
            <h4><i class="fas fa-building-columns"></i> Riwayat Deposit / Upgrade</h4>
            <button class="btn-add" onclick="toggleAdminDepoForm()">${adminShowDepoForm ? '— Tutup Form' : '+ Tambah Deposit Manual'}</button>
            ${adminShowDepoForm ? `
            <div class="admin-form">
                ${supabaseClient ? '<input type="text" id="adminDepoUserId" placeholder="User ID (UUID, opsional — untuk kredit poin otomatis)" maxlength="40">' : ''}
                <div class="form-row">
                    <input type="text" id="adminDepoUserName" placeholder="Nama User" maxlength="60">
                    <input type="number" id="adminDepoPoints" placeholder="Nominal (Rp / poin)" min="0" step="1000">
                </div>
                <div class="form-row">
                    <select id="adminDepoMethod">
                        <option value="Transfer Bank">Transfer Bank</option>
                        <option value="QRIS">QRIS</option>
                        <option value="DANA">DANA</option>
                        <option value="OVO">OVO</option>
                        <option value="GoPay">GoPay</option>
                        <option value="Lainnya">Lainnya</option>
                    </select>
                    <select id="adminDepoStatus">
                        <option value="approved">Disetujui</option>
                        <option value="pending">Pending</option>
                        <option value="rejected">Ditolak</option>
                    </select>
                </div>
                <p style="font-size:11px;color:#888;margin-bottom:6px;"><i class="fas fa-circle-info"></i> Deposit "Disetujui" + User ID terisi otomatis menambah poin user saat dibuat (1 poin = Rp 1).</p>
                <div class="form-actions">
                    <button class="btn-add" onclick="saveDepoAdmin()"><i class="fas fa-floppy-disk"></i> ${adminEditingDepoId ? 'Simpan Perubahan' : 'Simpan Deposit'}</button>
                    <button class="btn-outline" onclick="cancelDepoEdit()">Batal</button>
                </div>
            </div>` : ''}
            ${depoList.length === 0 ? '<p style="font-size:12px;color:#888;">Belum ada transaksi deposit.</p>' :
            depoList.map(r => {
                const isPending = (r.status || 'pending') === 'pending';
                return `
                <div class="upgrade-request-item">
                    <div class="ur-info">
                        <span class="ur-user">${esc(r.user_name || r.user)}</span>
                        <span class="ur-type">${esc(r.note || '')}${r.note ? ' • ' : ''}${esc(r.method || r.type || '')}</span>
                        <span class="ur-amount">${esc(r.amount)}</span>
                        <span class="ur-status ${esc(r.status || 'pending')}">${esc(String(r.status || 'pending').toUpperCase())}</span>
                    </div>
                    <div class="ur-actions">
                        ${r.proof_image ? `<button class="btn-outline" style="padding:4px 10px;font-size:11px;" onclick="openProofModal('${esc(r.id)}')"><i class="fas fa-image"></i> Lihat Bukti</button>` : ''}
                        ${isPending ? `
                        <button class="btn-approve" onclick="approveUpgradeAdmin('${esc(r.id)}')"><i class="fas fa-circle-check"></i> Setujui</button>
                        <button class="btn-reject" onclick="rejectUpgradeAdmin('${esc(r.id)}')"><i class="fas fa-circle-xmark"></i> Tolak</button>` : ''}
                        <button class="btn-edit" onclick="editDepoAdmin('${esc(r.id)}')"><i class="fas fa-pen"></i></button>
                        <button class="btn-delete-mission" onclick="deleteDepoAdmin('${esc(r.id)}')"><i class="fas fa-trash-can"></i></button>
                    </div>
                </div>`;
            }).join('')}
        </div>
    `;

    // ---------- TAB: USER ----------
    const usersTab = `
        <div class="admin-section">
            <h4><i class="fas fa-users"></i> Daftar User</h4>
            <button class="btn-add" onclick="toggleAdminUserForm()">${adminShowUserForm ? '— Tutup Form' : '+ Tambah User'}</button>
            ${adminShowUserForm ? `
            <div class="admin-form">
                ${supabaseClient && !adminEditingUserId ? '<input type="text" id="adminUserAuthId" placeholder="Auth User ID (UUID, dari Supabase Auth)" maxlength="40">' : ''}
                <div class="form-row">
                    <input type="text" id="adminUserName" placeholder="Nama Lengkap" maxlength="60">
                    <input type="text" id="adminUserPhone" placeholder="No. HP / WhatsApp" maxlength="20">
                </div>
                <div class="form-row">
                    <input type="number" id="adminUserPoints" placeholder="Poin (default 100)" min="0">
                    <select id="adminUserLevel">
                        <option value="Free">Free</option>
                        <option value="YouTube VIP">YouTube VIP</option>
                        <option value="Ads VIP">Ads VIP</option>
                        <option value="Premium">Premium</option>
                    </select>
                </div>
                <input type="text" id="adminUserReferral" placeholder="Kode Referral (kosong = otomatis)" maxlength="20">
                <label class="chk"><input type="checkbox" id="adminUserIsAdmin"> Jadikan Admin</label>
                <div class="form-actions">
                    <button class="btn-add" onclick="saveUserAdmin()"><i class="fas fa-floppy-disk"></i> ${adminEditingUserId ? 'Simpan Perubahan' : 'Simpan User'}</button>
                    <button class="btn-outline" onclick="cancelUserEdit()">Batal</button>
                </div>
            </div>` : ''}
            ${adminUsers.length === 0 ? '<p style="font-size:12px;color:#888;">Tidak ada user.</p>' :
            adminUsers.map(u => `
                <div class="admin-user-item">
                    <div>
                        <div class="u-name">${esc(u.full_name || u.name || 'User')} ${u.is_admin ? '<span class="badge-admin">ADMIN</span>' : ''}</div>
                        <div class="u-meta">${esc(u.phone || '')}${u.level ? ' • ' + esc(u.level) : ''}${u.referral_code ? ' • ' + esc(u.referral_code) : ''}</div>
                    </div>
                    <div style="text-align:right;display:flex;flex-direction:column;align-items:flex-end;gap:4px;">
                        <div class="u-points">${Number(u.points || 0).toLocaleString()} pts</div>
                        <div style="display:flex;gap:4px;">
                            <button class="btn-edit" onclick="editUserAdmin('${esc(u.id)}')"><i class="fas fa-pen"></i></button>
                            <button class="btn-delete-mission" onclick="deleteUserAdmin('${esc(u.id)}')"><i class="fas fa-trash-can"></i></button>
                        </div>
                    </div>
                </div>`).join('')}
        </div>
    `;

    // ---------- TAB: MISI ----------
    const missionsTab = `
        <div class="admin-section">
            <h4><i class="fas fa-video"></i> Kelola Misi Video & Ads</h4>
            <input type="text" id="adminMissionTitle" placeholder="Judul Misi Baru (Misal: Nonton Trailer Game)" maxlength="80">
            <input type="number" id="adminMissionPoints" placeholder="Jumlah Poin (Misal: 75)" min="1" max="1000">
            <select id="adminMissionType">
                <option value="youtube">YouTube Video</option>
                <option value="monetag">Monetag Ads</option>
                <option value="sosmed">Sosmed Link</option>
                <option value="daily">Daily Check-in</option>
                <option value="share">Share</option>
            </select>
            <input type="url" id="adminMissionLink" placeholder="Link/URL Misi (opsional) — contoh: https://www.youtube.com/embed/xxxx" maxlength="300">
            <div style="display:flex;gap:8px;margin-top:4px;">
                <button class="btn-add" onclick="addNewMissionAdmin()">${adminEditingMissionId ? '<i class="fas fa-floppy-disk"></i> Simpan Perubahan Misi' : '<i class="fas fa-plus"></i> Tambah Misi Baru'}</button>
                ${adminEditingMissionId ? '<button class="btn-outline" onclick="cancelMissionEdit()">Batal Edit</button>' : ''}
            </div>

            <div class="mission-list">
                ${missions.map(m => `
                    <div class="mission-item">
                        <div class="mission-info">
                            <div class="mission-name">${esc(m.name)}</div>
                            <div class="mission-detail">+${esc(m.points)} Poin • Type: ${esc(m.type)}${m.link ? ' • <i class="fas fa-link"></i> ada link' : ''}</div>
                        </div>
                        <div style="display:flex;gap:4px;">
                            <button class="btn-edit" onclick="editMissionAdmin(${esc(m.id)})"><i class="fas fa-pen"></i> Edit</button>
                            <button class="btn-delete-mission" onclick="deleteMissionAdmin(${esc(m.id)})">Hapus</button>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;

    // ---------- TAB: SETTING ----------
    const settingsTab = `
        <div class="admin-section">
            <h4><i class="fas fa-gear"></i> Pengaturan & Akun Admin</h4>
            <div class="account-info">
                <div class="row"><span class="label">Nama Admin:</span><span class="value">${esc(currentUser.name)}</span></div>
                <div class="row"><span class="label">Email:</span><span class="value">${esc(currentUser.email || '-')}</span></div>
                <div class="row"><span class="label">Mode Data:</span><span class="value">${supabaseClient ? 'Supabase (server)' : 'Demo (lokal)'}</span></div>
            </div>
            <div class="account-menu">
                <a href="dashboard.html" class="menu-item" style="text-decoration:none;color:inherit;">
                    <span class="icon"><i class="fas fa-mobile-screen-button"></i></span>
                    <span class="text">Buka Dashboard Member</span>
                    <span class="arrow">›</span>
                </a>
                <div class="menu-item danger" onclick="signOutSupabase()">
                    <span class="icon"><i class="fas fa-right-from-bracket"></i></span>
                    <span class="text">Keluar (Logout)</span>
                    <span class="arrow">›</span>
                </div>
            </div>
            <p style="font-size:11px;color:#999;margin-top:12px;">
                <i class="fas fa-circle-info"></i> QRIS & pembayaran masih simulasi. Hubungkan payment provider untuk verifikasi pembayaran sungguhan.
            </p>
        </div>

        <div class="admin-section">
            <h4><i class="fas fa-building-columns"></i> Kelola Bank Manual (Transfer Member)</h4>
            <p style="font-size:12px;color:#888;margin-bottom:8px;">Rekening ini tampil di halaman member (tab Upgrade) sebagai tujuan transfer manual. Hanya bank aktif yang ditampilkan.</p>
            <button class="btn-add" onclick="toggleAdminBankForm()">${adminShowBankForm ? '— Tutup Form' : '+ Tambah Bank'}</button>
            ${adminShowBankForm ? `
            <div class="admin-form">
                <div class="form-row">
                    <input type="text" id="adminBankName" placeholder="Nama Bank (BCA / BNI / DANA...)" maxlength="40">
                    <input type="text" id="adminBankNumber" placeholder="No. Rekening" maxlength="30">
                </div>
                <input type="text" id="adminBankHolder" placeholder="Atas Nama (a.n.)" maxlength="60">
                <label class="chk"><input type="checkbox" id="adminBankActive" checked> Aktif (tampil di member)</label>
                <div class="form-actions">
                    <button class="btn-add" onclick="saveBankAdmin()"><i class="fas fa-floppy-disk"></i> ${adminEditingBankId ? 'Simpan Perubahan' : 'Simpan Bank'}</button>
                    <button class="btn-outline" onclick="cancelBankEdit()">Batal</button>
                </div>
            </div>` : ''}
            <div class="bank-list">
                ${banks.length === 0 ? '<p style="font-size:12px;color:#888;">Belum ada bank.</p>' :
                banks.map(b => `
                    <div class="bank-item">
                        <div>
                            <div class="b-name">${esc(b.bank_name)} ${b.is_active === false ? '<span class="default-badge">nonaktif</span>' : ''}</div>
                            <div class="b-holder">${esc(b.account_name || '-')} • <span class="b-acc" onclick="copyBankNumber('${esc(String(b.account_number))}')">${esc(b.account_number)}</span></div>
                        </div>
                        <div style="display:flex;gap:4px;">
                            <button class="btn-edit" onclick="editBankAdmin(${esc(b.id)})"><i class="fas fa-pen"></i></button>
                            <button class="btn-delete-mission" onclick="deleteBankAdmin(${esc(b.id)})"><i class="fas fa-trash-can"></i></button>
                        </div>
                    </div>`).join('')}
            </div>
        </div>
    `;

    container.innerHTML = `
        <div class="admin-tab-content ${adminActiveTab === 'stats' ? 'active' : ''}" id="adminTab-stats">${statsTab}</div>
        <div class="admin-tab-content ${adminActiveTab === 'tx' ? 'active' : ''}" id="adminTab-tx">${txTab}</div>
        <div class="admin-tab-content ${adminActiveTab === 'users' ? 'active' : ''}" id="adminTab-users">${usersTab}</div>
        <div class="admin-tab-content ${adminActiveTab === 'missions' ? 'active' : ''}" id="adminTab-missions">${missionsTab}</div>
        <div class="admin-tab-content ${adminActiveTab === 'settings' ? 'active' : ''}" id="adminTab-settings">${settingsTab}</div>

        <!-- BOTTOM NAV ADMIN (seperti dashboard) -->
        <div class="bottom-nav admin-bottom-nav">
            <div class="nav-item ${adminActiveTab === 'stats' ? 'active' : ''}" data-atab="stats" onclick="switchAdminTab('stats')">
                <i class="fas fa-chart-bar"></i><span>Statistik</span>
            </div>
            <div class="nav-item ${adminActiveTab === 'tx' ? 'active' : ''}" data-atab="tx" onclick="switchAdminTab('tx')">
                <i class="fas fa-exchange-alt"></i><span>Transaksi</span>
            </div>
            <div class="nav-item ${adminActiveTab === 'users' ? 'active' : ''}" data-atab="users" onclick="switchAdminTab('users')">
                <i class="fas fa-users"></i><span>User</span>
            </div>
            <div class="nav-item ${adminActiveTab === 'missions' ? 'active' : ''}" data-atab="missions" onclick="switchAdminTab('missions')">
                <i class="fas fa-tasks"></i><span>Misi</span>
            </div>
            <div class="nav-item ${adminActiveTab === 'settings' ? 'active' : ''}" data-atab="settings" onclick="switchAdminTab('settings')">
                <i class="fas fa-cog"></i><span>Setting</span>
            </div>
        </div>
    `;
}

// Pindah tab panel admin (bottom nav)
function switchAdminTab(tabName) {
    adminActiveTab = tabName;
    document.querySelectorAll('.admin-tab-content').forEach(t => {
        t.classList.toggle('active', t.id === 'adminTab-' + tabName);
    });
    document.querySelectorAll('.admin-bottom-nav .nav-item').forEach(n => {
        n.classList.toggle('active', n.getAttribute('data-atab') === tabName);
    });
}

// Pindah sub-tab Transaksi (WD / Depo)
function switchAdminTxTab(tabName) {
    adminActiveTxTab = tabName;
    const wd = document.getElementById('adminTxWd');
    const depo = document.getElementById('adminTxDepo');
    if (wd) wd.classList.toggle('admin-hidden', tabName !== 'wd');
    if (depo) depo.classList.toggle('admin-hidden', tabName !== 'depo');
    document.querySelectorAll('.admin-tx-tab').forEach(b => {
        b.classList.toggle('active', b.getAttribute('data-txtab') === tabName);
    });
}

// Setujui/Tolak deposit — di Supabase pakai tabel `deposits`, di demo pakai state lokal.
async function approveUpgradeAdmin(id) {
    if (!currentUser || !currentUser.isAdmin) return;
    if (supabaseClient) {
        const { error } = await supabaseClient.from('deposits').update({ status: 'approved' }).eq('id', id);
        if (error) {
            showToast(`⚠️ Gagal menyetujui: ${error.message}`, 'error');
            return;
        }
        await loadAdminDataFromServer();
    } else {
        upgradeRequests = upgradeRequests.map(r => (r.id === id ? { ...r, status: 'approved' } : r));
        saveData();
    }
    showToast('✅ Deposit disetujui!', 'success');
    renderAdminPanel();
}

async function rejectUpgradeAdmin(id) {
    if (!currentUser || !currentUser.isAdmin) return;
    if (supabaseClient) {
        const { error } = await supabaseClient.from('deposits').update({ status: 'rejected' }).eq('id', id);
        if (error) {
            showToast(`⚠️ Gagal menolak: ${error.message}`, 'error');
            return;
        }
        await loadAdminDataFromServer();
    } else {
        upgradeRequests = upgradeRequests.map(r => (r.id === id ? { ...r, status: 'rejected' } : r));
        saveData();
    }
    showToast('❌ Deposit ditolak.', 'info');
    renderAdminPanel();
}

// ==================== ADMIN: CRUD USER ====================
// Daftar deposit yang ditampilkan admin: tabel `deposits` (Supabase) atau
// `upgradeRequests` (mode demo).
function getDeposits() {
    return supabaseClient ? deposits : upgradeRequests;
}

function toggleAdminUserForm() {
    adminShowUserForm = !adminShowUserForm;
    if (!adminShowUserForm) adminEditingUserId = null;
    renderAdminPanel();
}

function cancelUserEdit() {
    adminEditingUserId = null;
    adminShowUserForm = false;
    renderAdminPanel();
}

function editUserAdmin(id) {
    const u = adminUsers.find(x => String(x.id) === String(id));
    if (!u) return;
    adminEditingUserId = id;
    adminShowUserForm = true;
    renderAdminPanel();
    const nameEl = document.getElementById('adminUserName');
    if (nameEl) nameEl.value = u.full_name || u.name || '';
    const phoneEl = document.getElementById('adminUserPhone');
    if (phoneEl) phoneEl.value = u.phone || '';
    const ptsEl = document.getElementById('adminUserPoints');
    if (ptsEl) ptsEl.value = u.points || 0;
    const levelEl = document.getElementById('adminUserLevel');
    if (levelEl) levelEl.value = u.level || 'Free';
    const isAdminEl = document.getElementById('adminUserIsAdmin');
    if (isAdminEl) isAdminEl.checked = !!u.is_admin;
    const refEl = document.getElementById('adminUserReferral');
    if (refEl) refEl.value = u.referral_code || '';
}

async function saveUserAdmin() {
    if (!currentUser || !currentUser.isAdmin) {
        showToast('⛔ Akses ditolak: Anda bukan admin.', 'error');
        return;
    }
    const name = (document.getElementById('adminUserName')?.value || '').trim();
    const phone = (document.getElementById('adminUserPhone')?.value || '').trim();
    const ptsRaw = parseInt(document.getElementById('adminUserPoints')?.value, 10);
    const pts = Number.isFinite(ptsRaw) && ptsRaw >= 0 ? ptsRaw : 0;
    const level = document.getElementById('adminUserLevel')?.value || 'Free';
    const isAdmin = document.getElementById('adminUserIsAdmin')?.checked || false;
    const ref = (document.getElementById('adminUserReferral')?.value || '').trim();
    const authId = (document.getElementById('adminUserAuthId')?.value || '').trim();

    if (!name) {
        showToast('Nama user wajib diisi.', 'warning');
        return;
    }

    if (supabaseClient) {
        try {
            if (adminEditingUserId) {
                const { error } = await supabaseClient.rpc('admin_update_profile', {
                    p_id: adminEditingUserId,
                    p_full_name: name,
                    p_phone: phone || null,
                    p_points: pts,
                    p_level: level,
                    p_is_admin: isAdmin,
                    p_referral_code: ref || null
                });
                if (error) { showToast(`⚠️ ${error.message}`, 'error'); return; }
            } else {
                if (!authId) {
                    showToast('⚠️ Mode Supabase: isi Auth User ID (UUID user yang sudah terdaftar di Supabase Auth).', 'warning');
                    return;
                }
                const { error } = await supabaseClient.rpc('admin_create_profile', {
                    p_auth_id: authId,
                    p_full_name: name,
                    p_phone: phone || null,
                    p_points: pts,
                    p_level: level,
                    p_is_admin: isAdmin,
                    p_referral_code: ref || null
                });
                if (error) { showToast(`⚠️ ${error.message}`, 'error'); return; }
            }
            await loadAdminUsersFromServer();
        } catch (e) {
            showToast(`⚠️ ${e.message}`, 'error');
            return;
        }
    } else {
        // Mode demo
        if (adminEditingUserId) {
            adminUsers = adminUsers.map(u => (String(u.id) === String(adminEditingUserId)
                ? { ...u, full_name: name, phone, points: pts, level, is_admin: isAdmin, referral_code: ref }
                : u));
        } else {
            adminUsers.unshift({
                id: 'USR-' + Date.now(),
                full_name: name,
                phone,
                points: pts,
                level,
                is_admin: isAdmin,
                referral_code: ref,
                created_at: new Date().toLocaleDateString()
            });
        }
        saveData();
    }

    adminEditingUserId = null;
    adminShowUserForm = false;
    showToast('✅ User disimpan!', 'success');
    renderAdminPanel();
}

async function deleteUserAdmin(id) {
    if (!currentUser || !currentUser.isAdmin) return;
    if (currentUser.id && String(currentUser.id) === String(id)) {
        showToast('⛔ Tidak bisa menghapus akun sendiri.', 'error');
        return;
    }
    if (!confirm('Hapus user ini? Tindakan tidak bisa dibatalkan.')) return;

    if (supabaseClient) {
        const { error } = await supabaseClient.rpc('admin_delete_profile', { p_id: id });
        if (error) {
            showToast(`⚠️ ${error.message}`, 'error');
            return;
        }
        await loadAdminUsersFromServer();
    } else {
        adminUsers = adminUsers.filter(u => String(u.id) !== String(id));
        saveData();
    }
    showToast('🗑️ User dihapus.', 'info');
    renderAdminPanel();
}

// ==================== ADMIN: CRUD WD MANUAL ====================
function toggleAdminWdForm() {
    adminShowWdForm = !adminShowWdForm;
    if (!adminShowWdForm) adminEditingWdId = null;
    renderAdminPanel();
}

function cancelWdEdit() {
    adminEditingWdId = null;
    adminShowWdForm = false;
    renderAdminPanel();
}

function editWdAdmin(id) {
    const w = withdrawRequests.find(x => String(x.id) === String(id));
    if (!w) return;
    adminEditingWdId = id;
    adminShowWdForm = true;
    renderAdminPanel();
    const nameEl = document.getElementById('adminWdUserName');
    if (nameEl) nameEl.value = w.user_name || '';
    const statusEl = document.getElementById('adminWdStatus');
    if (statusEl) statusEl.value = w.status || 'pending';
    const ptsEl = document.getElementById('adminWdPoints');
    if (ptsEl) ptsEl.value = w.points || 0;
    const methodEl = document.getElementById('adminWdMethod');
    if (methodEl) methodEl.value = w.method || '';
}

async function saveWdAdmin() {
    if (!currentUser || !currentUser.isAdmin) return;
    const userName = (document.getElementById('adminWdUserName')?.value || '').trim();
    const pts = parseInt(document.getElementById('adminWdPoints')?.value, 10);
    const method = (document.getElementById('adminWdMethod')?.value || 'Manual').trim();
    const status = document.getElementById('adminWdStatus')?.value || 'pending';

    if (!Number.isFinite(pts) || pts <= 0) {
        showToast('Nominal (Rp / poin) wajib diisi lebih dari 0.', 'warning');
        return;
    }
    const amount = 'Rp ' + pts.toLocaleString('id-ID');

    if (supabaseClient) {
        try {
            if (adminEditingWdId) {
                const { error } = await supabaseClient
                    .from('withdrawals')
                    .update({ amount, points: pts, method, status, user_name: userName || null })
                    .eq('id', adminEditingWdId);
                if (error) { showToast(`⚠️ ${error.message}`, 'error'); return; }
            } else {
                const { error } = await supabaseClient
                    .from('withdrawals')
                    .insert({ id: 'WD-' + Date.now(), user_id: null, user_name: userName || null, amount, points: pts, method, status });
                if (error) { showToast(`⚠️ ${error.message}`, 'error'); return; }
            }
            await loadAdminDataFromServer();
        } catch (e) {
            showToast(`⚠️ ${e.message}`, 'error');
            return;
        }
    } else {
        if (adminEditingWdId) {
            withdrawRequests = withdrawRequests.map(w => (String(w.id) === String(adminEditingWdId)
                ? { ...w, user_name: userName, amount, points: pts, method, status }
                : w));
        } else {
            withdrawRequests.unshift({
                id: 'WD-' + Date.now(),
                user_name: userName,
                amount,
                points: pts,
                method,
                status,
                date: new Date().toLocaleDateString()
            });
        }
        saveData();
    }

    adminEditingWdId = null;
    adminShowWdForm = false;
    recomputeAdminStats();
    showToast('✅ WD disimpan!', 'success');
    renderAdminPanel();
}

async function deleteWdAdmin(id) {
    if (!currentUser || !currentUser.isAdmin) return;
    if (!confirm('Hapus penarikan ini?')) return;

    if (supabaseClient) {
        const { error } = await supabaseClient.from('withdrawals').delete().eq('id', id);
        if (error) {
            showToast(`⚠️ ${error.message}`, 'error');
            return;
        }
        await loadAdminDataFromServer();
    } else {
        withdrawRequests = withdrawRequests.filter(w => String(w.id) !== String(id));
        saveData();
    }
    recomputeAdminStats();
    showToast('🗑️ Penarikan dihapus.', 'info');
    renderAdminPanel();
}

// ==================== ADMIN: CRUD DEPOSIT MANUAL ====================
function toggleAdminDepoForm() {
    adminShowDepoForm = !adminShowDepoForm;
    if (!adminShowDepoForm) adminEditingDepoId = null;
    renderAdminPanel();
}

function cancelDepoEdit() {
    adminEditingDepoId = null;
    adminShowDepoForm = false;
    renderAdminPanel();
}

function editDepoAdmin(id) {
    const r = getDeposits().find(x => String(x.id) === String(id));
    if (!r) return;
    adminEditingDepoId = id;
    adminShowDepoForm = true;
    renderAdminPanel();
    const userIdEl = document.getElementById('adminDepoUserId');
    if (userIdEl) userIdEl.value = r.user_id || '';
    const nameEl = document.getElementById('adminDepoUserName');
    if (nameEl) nameEl.value = r.user_name || r.user || '';
    const ptsEl = document.getElementById('adminDepoPoints');
    if (ptsEl) ptsEl.value = r.points || 0;
    const methodEl = document.getElementById('adminDepoMethod');
    if (methodEl) methodEl.value = r.method || r.type || 'Transfer Bank';
    const statusEl = document.getElementById('adminDepoStatus');
    if (statusEl) statusEl.value = r.status || 'approved';
}

async function saveDepoAdmin() {
    if (!currentUser || !currentUser.isAdmin) return;
    const userId = (document.getElementById('adminDepoUserId')?.value || '').trim() || null;
    const userName = (document.getElementById('adminDepoUserName')?.value || '').trim();
    const pts = parseInt(document.getElementById('adminDepoPoints')?.value, 10);
    const method = document.getElementById('adminDepoMethod')?.value || 'Transfer Bank';
    const status = document.getElementById('adminDepoStatus')?.value || 'approved';

    if (!Number.isFinite(pts) || pts <= 0) {
        showToast('Nominal (Rp / poin) wajib diisi lebih dari 0.', 'warning');
        return;
    }
    const amount = 'Rp ' + pts.toLocaleString('id-ID');

    if (supabaseClient) {
        try {
            if (adminEditingDepoId) {
                const { error } = await supabaseClient
                    .from('deposits')
                    .update({ user_id: userId, user_name: userName || null, amount, points: pts, method, status })
                    .eq('id', adminEditingDepoId);
                if (error) { showToast(`⚠️ ${error.message}`, 'error'); return; }
            } else {
                const id = 'DEP-' + Date.now();
                const { error } = await supabaseClient
                    .from('deposits')
                    .insert({ id, user_id: userId, user_name: userName || null, amount, points: pts, method, status });
                if (error) { showToast(`⚠️ ${error.message}`, 'error'); return; }
                // Deposit disetujui + user terisi => kredit poin otomatis
                if (status === 'approved' && userId) {
                    const credit = await supabaseClient.rpc('admin_credit_points', { p_user_id: userId, p_points: pts });
                    if (credit.error) showToast(`⚠️ Poin tidak bisa dikredit: ${credit.error.message}`, 'warning');
                    else showToast(`💰 +${pts.toLocaleString()} poin dikredit ke user.`, 'success');
                }
            }
            await loadAdminDataFromServer();
        } catch (e) {
            showToast(`⚠️ ${e.message}`, 'error');
            return;
        }
    } else {
        if (adminEditingDepoId) {
            upgradeRequests = upgradeRequests.map(r => (String(r.id) === String(adminEditingDepoId)
                ? { ...r, user: userName, type: method, amount, status }
                : r));
        } else {
            upgradeRequests.unshift({
                id: 'UPG-' + Date.now(),
                user: userName || 'Member',
                type: method,
                amount,
                points: pts,
                date: new Date().toLocaleDateString(),
                status
            });
        }
        saveData();
    }

    adminEditingDepoId = null;
    adminShowDepoForm = false;
    showToast('✅ Deposit disimpan!', 'success');
    renderAdminPanel();
}

async function deleteDepoAdmin(id) {
    if (!currentUser || !currentUser.isAdmin) return;
    if (!confirm('Hapus transaksi deposit ini?')) return;

    if (supabaseClient) {
        const { error } = await supabaseClient.from('deposits').delete().eq('id', id);
        if (error) {
            showToast(`⚠️ ${error.message}`, 'error');
            return;
        }
        await loadAdminDataFromServer();
    } else {
        upgradeRequests = upgradeRequests.filter(r => String(r.id) !== String(id));
        saveData();
    }
    showToast('🗑️ Deposit dihapus.', 'info');
    renderAdminPanel();
}

// ==================== ADMIN: CRUD BANK MANUAL ====================
function toggleAdminBankForm() {
    adminShowBankForm = !adminShowBankForm;
    if (!adminShowBankForm) adminEditingBankId = null;
    renderAdminPanel();
}

function cancelBankEdit() {
    adminEditingBankId = null;
    adminShowBankForm = false;
    renderAdminPanel();
}

function editBankAdmin(id) {
    const b = banks.find(x => String(x.id) === String(id));
    if (!b) return;
    adminEditingBankId = id;
    adminShowBankForm = true;
    renderAdminPanel();
    const nameEl = document.getElementById('adminBankName');
    if (nameEl) nameEl.value = b.bank_name || '';
    const numEl = document.getElementById('adminBankNumber');
    if (numEl) numEl.value = b.account_number || '';
    const holderEl = document.getElementById('adminBankHolder');
    if (holderEl) holderEl.value = b.account_name || '';
    const activeEl = document.getElementById('adminBankActive');
    if (activeEl) activeEl.checked = b.is_active !== false;
}

async function saveBankAdmin() {
    if (!currentUser || !currentUser.isAdmin) return;
    const bankName = (document.getElementById('adminBankName')?.value || '').trim();
    const accountNumber = (document.getElementById('adminBankNumber')?.value || '').trim();
    const accountName = (document.getElementById('adminBankHolder')?.value || '').trim();
    const isActive = document.getElementById('adminBankActive')?.checked !== false;

    if (!bankName || !accountNumber) {
        showToast('Nama bank dan no. rekening wajib diisi.', 'warning');
        return;
    }

    if (supabaseClient) {
        try {
            if (adminEditingBankId) {
                const { error } = await supabaseClient
                    .from('banks')
                    .update({ bank_name: bankName, account_name: accountName || null, account_number: accountNumber, is_active: isActive })
                    .eq('id', adminEditingBankId);
                if (error) { showToast(`⚠️ ${error.message}`, 'error'); return; }
            } else {
                const { error } = await supabaseClient
                    .from('banks')
                    .insert({ bank_name: bankName, account_name: accountName || null, account_number: accountNumber, is_active: isActive });
                if (error) { showToast(`⚠️ ${error.message}`, 'error'); return; }
            }
            await loadBanksFromServer();
        } catch (e) {
            showToast(`⚠️ ${e.message}`, 'error');
            return;
        }
    } else {
        if (adminEditingBankId) {
            banks = banks.map(b => (String(b.id) === String(adminEditingBankId)
                ? { ...b, bank_name: bankName, account_name: accountName, account_number: accountNumber, is_active: isActive }
                : b));
        } else {
            banks.push({ id: 'BANK-' + Date.now(), bank_name: bankName, account_name: accountName, account_number: accountNumber, is_active: isActive });
        }
        saveData();
    }

    adminEditingBankId = null;
    adminShowBankForm = false;
    showToast('✅ Bank disimpan!', 'success');
    renderAdminPanel();
}

async function deleteBankAdmin(id) {
    if (!currentUser || !currentUser.isAdmin) return;
    if (!confirm('Hapus bank ini?')) return;

    if (supabaseClient) {
        const { error } = await supabaseClient.from('banks').delete().eq('id', id);
        if (error) {
            showToast(`⚠️ ${error.message}`, 'error');
            return;
        }
        await loadBanksFromServer();
    } else {
        banks = banks.filter(b => String(b.id) !== String(id));
        saveData();
    }
    showToast('🗑️ Bank dihapus.', 'info');
    renderAdminPanel();
}

async function addNewMissionAdmin() {
    if (!currentUser || !currentUser.isAdmin) {
        showToast('⛔ Akses ditolak: Anda bukan admin.', 'error');
        return;
    }

    const title = document.getElementById('adminMissionTitle').value.trim();
    const pts = parseInt(document.getElementById('adminMissionPoints').value, 10);
    const type = document.getElementById('adminMissionType').value;
    const linkRaw = document.getElementById('adminMissionLink').value.trim();

    if (!title || !pts || !Number.isFinite(pts) || pts <= 0 || pts > 1000) {
        showToast('Isi judul (maks 80 karakter) dan jumlah poin (1–1000)!', 'warning');
        return;
    }

    // Link opsional: harus URL absolut http/https
    let link = null;
    if (linkRaw) {
        link = safeExternalLink(linkRaw);
        if (link === '#') {
            showToast('Link tidak valid: gunakan URL lengkap http:// atau https://', 'warning');
            return;
        }
    }

    if (supabaseClient) {
        if (adminEditingMissionId) {
            // Update misi yang sedang diedit (policy: hanya admin)
            const { data, error } = await supabaseClient
                .from('missions')
                .update({ name: title, points: pts, type: type, link: link })
                .eq('id', adminEditingMissionId)
                .select()
                .single();
            if (error) {
                showToast(`⚠️ Gagal menyimpan misi: ${error.message}`, 'error');
                return;
            }
            if (data) missions = missions.map(m => (m.id === adminEditingMissionId ? mapServerMission(data) : m));
        } else {
            // Simpan ke tabel `missions` di Supabase (policy: hanya admin)
            const { data, error } = await supabaseClient
                .from('missions')
                .insert({ name: title, desc_text: 'Misi tambahan dari admin', points: pts, type: type, link: link })
                .select()
                .single();
            if (error) {
                showToast(`⚠️ Gagal menyimpan misi: ${error.message}`, 'error');
                return;
            }
            if (data) missions.push(mapServerMission(data));
        }
    } else {
        // Mode demo: state lokal (tambah atau update)
        if (adminEditingMissionId) {
            missions = missions.map(m => (m.id === adminEditingMissionId ? { ...m, name: title, points: pts, type: type, link: link || undefined, isYoutube: type === 'youtube', isMonetag: type === 'monetag' } : m));
        } else {
            missions.push({
                id: Date.now(),
                name: title,
                desc: 'Misi tambahan dari admin',
                points: pts,
                type: type,
                link: link || undefined,
                isYoutube: type === 'youtube',
                isMonetag: type === 'monetag'
            });
        }
    }

    adminEditingMissionId = null;
    saveData();
    showToast('✅ Misi berhasil disimpan!', 'success');
    renderAdminPanel();
    renderMissions();
}

// Mode edit misi: isi form dengan data misi yang dipilih.
function editMissionAdmin(id) {
    const m = missions.find(x => String(x.id) === String(id));
    if (!m) return;
    adminEditingMissionId = id;
    renderAdminPanel();
    document.getElementById('adminMissionTitle').value = m.name || '';
    document.getElementById('adminMissionPoints').value = m.points || '';
    document.getElementById('adminMissionType').value = m.type || 'youtube';
    document.getElementById('adminMissionLink').value = m.link || '';
    showToast(`✏️ Edit misi: ${m.name}`, 'info');
}

function cancelMissionEdit() {
    adminEditingMissionId = null;
    renderAdminPanel();
}

async function deleteMissionAdmin(id) {
    if (!currentUser || !currentUser.isAdmin) {
        showToast('⛔ Akses ditolak: Anda bukan admin.', 'error');
        return;
    }

    if (supabaseClient) {
        // Hapus dari tabel `missions` di Supabase (policy: hanya admin)
        const { error } = await supabaseClient
            .from('missions')
            .delete()
            .eq('id', id);
        if (error) {
            showToast(`⚠️ Gagal menghapus misi: ${error.message}`, 'error');
            return;
        }
    }

    missions = missions.filter(m => m.id !== id);
    saveData();
    showToast('🗑️ Misi berhasil dihapus.', 'info');
    renderAdminPanel();
    renderMissions();
}

async function approveWithdrawAdmin(id) {
    if (!currentUser || !currentUser.isAdmin) return;

    if (supabaseClient) {
        // Update status di tabel `withdrawals` (policy: hanya admin)
        const { error } = await supabaseClient
            .from('withdrawals')
            .update({ status: 'approved' })
            .eq('id', id);
        if (error) {
            showToast(`⚠️ Gagal menyetujui: ${error.message}`, 'error');
            return;
        }
    }

    const item = withdrawHistory.find(w => w.id === id);
    if (item) item.status = 'approved';
    withdrawRequests = withdrawRequests.map(w => (w.id === id ? { ...w, status: 'approved' } : w));
    saveData();
    recomputeAdminStats();
    showToast(`✅ Penarikan ${id} disetujui!`, 'success');
    renderAdminPanel();
    updateUI();
}

async function rejectWithdrawAdmin(id) {
    if (!currentUser || !currentUser.isAdmin) return;

    if (supabaseClient) {
        const { error } = await supabaseClient
            .from('withdrawals')
            .update({ status: 'rejected' })
            .eq('id', id);
        if (error) {
            showToast(`⚠️ Gagal menolak: ${error.message}`, 'error');
            return;
        }
    }

    const item = withdrawHistory.find(w => w.id === id);
    if (item) item.status = 'rejected';
    withdrawRequests = withdrawRequests.map(w => (w.id === id ? { ...w, status: 'rejected' } : w));
    saveData();
    recomputeAdminStats();
    showToast(`❌ Penarikan ${id} ditolak.`, 'info');
    renderAdminPanel();
    updateUI();
}

// ==================== AUTO INITIALIZE ON LOAD ====================
document.addEventListener('DOMContentLoaded', async () => {
    loadData();
    const configured = initSupabase();
    if (configured) {
        await checkSupabaseSession();
        // Saat Supabase aktif: misi & riwayat penarikan diambil dari database
        if (currentUser && currentUser.id) {
            await Promise.all([loadMissionsFromServer(), fetchMyWithdrawals()]);
        }
    }

    const path = window.location.pathname;
    const onAuthPage = path.includes('login.html') || path.includes('register.html') || path.includes('reset-password.html');
    const isDashboard = path.includes('dashboard.html');
    const isAdminPage = path.includes('admin.html');

    if (!currentUser) {
        // Halaman yang butuh login: arahkan ke login bila Supabase aktif
        if (configured && (isDashboard || isAdminPage)) {
            showToast('⚠️ Silakan login terlebih dahulu.', 'warning');
            setTimeout(() => { window.location.href = 'login.html'; }, 800);
            return;
        }
        // Mode demo (Supabase belum dikonfigurasi): login demo eksplisit,
        // hanya di dashboard, dan status admin SELALU false.
        if (!configured && isDashboard) {
            performLoginDemo('Member MisiPulsa', '08123456789');
            return;
        }
        updateUI();
        return;
    }

    if (isAdminPage && !currentUser.isAdmin) {
        showToast('⛔ Akses ditolak: hanya admin yang dapat membuka panel ini.', 'error');
        setTimeout(() => { window.location.href = 'login.html'; }, 1200);
        return;
    }

    updateUI();
});
