-- ==========================================================================
-- MISIPULSA - SUPABASE DATABASE SETUP SCRIPT (SECURED)
-- Copy dan Paste script ini di SQL Editor Dashboard Supabase Anda
--
-- Perubahan keamanan:
--   1. Status admin hanya dibaca dari kolom profiles.is_admin; user TIDAK
--      bisa mengubah is_admin / points / referral_code sendiri (column grants).
--   2. Profil tidak lagi terbaca publik: user hanya bisa melihat dirinya
--      sendiri (atau admin melihat semua).
--   3. Klaim misi & penambahan poin hanya lewat RPC record_mission_claim
--      (SECURITY DEFINER) yang memvalidasi di server. Insert user_missions
--      langsung oleh client DIBLOKIR.
--   4. Trigger handle_new_user: kode referral anti-collision (loop retry)
--      dan bonus referral +50 poin untuk perekrut.
--   5. Misi (missions) hanya bisa dikelola admin; user biasa read-only.
-- ==========================================================================

-- 1. TABEL PROFILES (Penyimpanan Data Pengguna)
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID REFERENCES auth.users ON DELETE CASCADE PRIMARY KEY,
    phone TEXT,
    full_name TEXT DEFAULT 'Member MisiPulsa',
    points INT DEFAULT 100,
    level TEXT DEFAULT 'Free',
    referral_code TEXT UNIQUE,
    streak INT DEFAULT 1,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- 2. TABEL MISSIONS (Daftar Misi)
CREATE TABLE IF NOT EXISTS public.missions (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    desc_text TEXT,
    points INT DEFAULT 50,
    type TEXT DEFAULT 'youtube',
    link TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- 3. TABEL WITHDRAWALS (Riwayat Penarikan Poin)
CREATE TABLE IF NOT EXISTS public.withdrawals (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
    amount TEXT NOT NULL,
    points INT NOT NULL,
    method TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- 4. TABEL USER_MISSIONS (Misi yang Sudah Diklaim User)
CREATE TABLE IF NOT EXISTS public.user_missions (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
    mission_id BIGINT REFERENCES public.missions(id) ON DELETE CASCADE,
    claimed_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_missions_user_claimed
    ON public.user_missions (user_id, claimed_at);

-- 5. TRIGGER OTOMATIS SAAT USER REGISTRASI BARU (AUTO PROFILE + 100 POIN)
--    Kode referral dibuat anti-collision (loop retry saat UNIQUE bentrok)
--    dan jika pendaftar membawa kode referral, perekrut mendapat +50 poin.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_ref_code TEXT;
    v_referrer_id UUID;
    v_referrer_code TEXT := NULLIF(UPPER(NEW.raw_user_meta_data->>'referral_code'), '');
BEGIN
    v_ref_code := UPPER('MISI' || SUBSTRING(REPLACE(NEW.id::text, '-', ''), 1, 6));
    LOOP
        BEGIN
            INSERT INTO public.profiles (id, phone, full_name, points, referral_code)
            VALUES (
                NEW.id,
                COALESCE(NEW.raw_user_meta_data->>'phone', NEW.phone, '08123456789'),
                COALESCE(NEW.raw_user_meta_data->>'full_name', 'Member Baru'),
                100, -- Bonus 100 Poin Otomatis Pendaftaran
                v_ref_code
            );
            EXIT;
        EXCEPTION WHEN unique_violation THEN
            v_ref_code := UPPER('MISI' || SUBSTRING(MD5(random()::text || NEW.id::text) FROM 1 FOR 6));
        END;
    END LOOP;

    -- Bonus referral +50 poin untuk perekrut
    IF v_referrer_code IS NOT NULL THEN
        SELECT id INTO v_referrer_id
          FROM public.profiles
         WHERE referral_code = v_referrer_code;
        IF v_referrer_id IS NOT NULL AND v_referrer_id <> NEW.id THEN
            UPDATE public.profiles
               SET points = COALESCE(points, 0) + 50
             WHERE id = v_referrer_id;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

-- JALANKAN TRIGGER
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 6. DUMMY DATA MISI AWAL
INSERT INTO public.missions (id, name, desc_text, points, type, link)
VALUES
    (1, 'Nonton YouTube 15 Detik', 'Tonton video YouTube singkat sampai selesai', 75, 'youtube', 'https://www.youtube.com/embed/dQw4w9WgXcQ'),
    (2, 'Tonton Iklan Sponsor', 'Selesaikan iklan singkat untuk klaim poin', 50, 'monetag', NULL),
    (3, 'Daily Check-in', 'Klaim bonus login harian kamu setiap hari', 10, 'daily', NULL),
    (4, 'Follow Instagram @misipulsa', 'Follow akun Instagram resmi kami', 30, 'sosmed', 'https://instagram.com'),
    (5, 'Bagikan ke WhatsApp', 'Bagikan info MisiPulsa ke grup WA', 40, 'share', 'https://whatsapp.com')
ON CONFLICT (id) DO NOTHING;

-- 7. SET RLS (ROW LEVEL SECURITY)
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.missions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.withdrawals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_missions ENABLE ROW LEVEL SECURITY;

-- ==========================================================================
-- Helper: cek apakah user yang sedang login adalah admin.
-- SECURITY DEFINER agar subquery is_admin tidak terhambat policy RLS.
-- ==========================================================================
CREATE OR REPLACE FUNCTION public.is_admin_user()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = auth.uid() AND is_admin
    );
$$;

REVOKE EXECUTE ON FUNCTION public.is_admin_user() FROM anon, public;
GRANT EXECUTE ON FUNCTION public.is_admin_user() TO authenticated;

-- ==========================================================================
-- RPC: Klaim misi & tambah poin (satu-satunya jalan menambah poin dari app).
-- Memvalidasi: misi ada, aturan harian/limit, mencegah klaim ganda.
-- Hanya dipanggil dengan JWT login (auth.uid()).
-- ==========================================================================
CREATE OR REPLACE FUNCTION public.record_mission_claim(p_mission_id BIGINT)
RETURNS INT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_mission RECORD;
    v_new_points INT;
    v_today DATE := DATE(NOW() AT TIME ZONE 'UTC');
BEGIN
    IF auth.uid() IS NULL THEN
        RAISE EXCEPTION 'Anda harus login untuk mengklaim misi.';
    END IF;

    SELECT * INTO v_mission FROM public.missions WHERE id = p_mission_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Misi tidak ditemukan.';
    END IF;

    IF v_mission.type IN ('youtube', 'monetag') THEN
        -- Misi video/iklan: boleh berulang, dibatasi 20x per hari per tipe
        IF (
            SELECT COUNT(*)
              FROM public.user_missions um
              JOIN public.missions ms ON ms.id = um.mission_id
             WHERE um.user_id = auth.uid()
               AND ms.type = v_mission.type
               AND DATE(um.claimed_at AT TIME ZONE 'UTC') = v_today
        ) >= 20 THEN
            RAISE EXCEPTION 'Limit harian untuk misi ini sudah habis.';
        END IF;
    ELSIF v_mission.type = 'daily' THEN
        -- Misi harian: maksimal 1x per hari
        IF EXISTS (
            SELECT 1 FROM public.user_missions um
            WHERE um.user_id = auth.uid()
              AND um.mission_id = p_mission_id
              AND DATE(um.claimed_at AT TIME ZONE 'UTC') = v_today
        ) THEN
            RAISE EXCEPTION 'Misi harian sudah diklaim hari ini.';
        END IF;
    ELSE
        -- Misi lain (sosmed/share): hanya sekali seumur hidup
        IF EXISTS (
            SELECT 1 FROM public.user_missions um
            WHERE um.user_id = auth.uid() AND um.mission_id = p_mission_id
        ) THEN
            RAISE EXCEPTION 'Misi ini sudah pernah diklaim.';
        END IF;
    END IF;

    INSERT INTO public.user_missions (user_id, mission_id)
    VALUES (auth.uid(), p_mission_id);

    UPDATE public.profiles
       SET points = COALESCE(points, 0) + COALESCE(v_mission.points, 0)
     WHERE id = auth.uid()
     RETURNING points INTO v_new_points;

    RETURN v_new_points;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.record_mission_claim(BIGINT) FROM anon, public;
GRANT EXECUTE ON FUNCTION public.record_mission_claim(BIGINT) TO authenticated;

-- ==========================================================================
-- POLICIES PROFILES
--   SELECT : hanya milik sendiri (admin bisa lihat semua)
--   UPDATE : hanya milik sendiri; kolom sensitif (points, is_admin,
--            referral_code) TIDAK BISA diubah user langsung
-- ==========================================================================
DROP POLICY IF EXISTS "Public profiles are viewable by everyone." ON public.profiles;
DROP POLICY IF EXISTS "Users can update own profile." ON public.profiles;

CREATE POLICY "Users can view own profile" ON public.profiles
    FOR SELECT USING (auth.uid() = id OR public.is_admin_user());

CREATE POLICY "Users can update own profile" ON public.profiles
    FOR UPDATE USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

-- Cabut hak update umum, lalu beri hanya kolom aman (profil pengguna).
REVOKE UPDATE ON public.profiles FROM anon, authenticated;
GRANT UPDATE (phone, full_name, streak) ON public.profiles TO authenticated;

-- ==========================================================================
-- POLICIES MISSIONS
--   SELECT : publik (bisa dilihat semua)
--   INSERT/UPDATE/DELETE : hanya admin
-- ==========================================================================
DROP POLICY IF EXISTS "Missions are viewable by everyone." ON public.missions;

CREATE POLICY "Missions are viewable by everyone." ON public.missions
    FOR SELECT USING (true);

CREATE POLICY "Admins can manage missions" ON public.missions
    FOR ALL USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());

-- ==========================================================================
-- POLICIES WITHDRAWALS
--   User: lihat & buat penarikan milik sendiri saja
--   Admin: lihat & update semua
-- ==========================================================================
DROP POLICY IF EXISTS "Users can view own withdrawals." ON public.withdrawals;
DROP POLICY IF EXISTS "Users can insert own withdrawals." ON public.withdrawals;

CREATE POLICY "Users can view own withdrawals." ON public.withdrawals
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own withdrawals." ON public.withdrawals
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Admins can view all withdrawals" ON public.withdrawals
    FOR SELECT USING (public.is_admin_user());

CREATE POLICY "Admins can update withdrawals" ON public.withdrawals
    FOR UPDATE USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());

-- ==========================================================================
-- POLICIES USER_MISSIONS
--   User: lihat riwayat klaim sendiri saja.
--   INSERT/UPDATE/DELETE langsung TIDAK diizinkan — hanya lewat RPC
--   record_mission_claim (mencegah user memberi poin ke dirinya sendiri).
-- ==========================================================================
CREATE POLICY "Users can view own mission claims" ON public.user_missions
    FOR SELECT USING (auth.uid() = user_id);

-- ==========================================================================
-- 8. TABEL BANKS (Rekening manual tujuan transfer member)
--     Tampil di dashboard member (tab Upgrade) + dikelola admin (tab Setting).
-- ==========================================================================
CREATE TABLE IF NOT EXISTS public.banks (
    id BIGSERIAL PRIMARY KEY,
    bank_name TEXT NOT NULL,
    account_name TEXT,
    account_number TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

ALTER TABLE public.banks ENABLE ROW LEVEL SECURITY;

-- Siapa pun boleh melihat daftar bank (member butuh nomor rekening tujuan).
DROP POLICY IF EXISTS "Banks are viewable by everyone." ON public.banks;
CREATE POLICY "Banks are viewable by everyone." ON public.banks
    FOR SELECT USING (true);

-- Hanya admin yang boleh menambah/mengubah/menghapus bank.
DROP POLICY IF EXISTS "Admins can manage banks" ON public.banks;
CREATE POLICY "Admins can manage banks" ON public.banks
    FOR ALL USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());

-- Seed bank awal (tidak dobel saat script dijalankan ulang)
INSERT INTO public.banks (bank_name, account_name, account_number)
SELECT 'BCA', 'PT MisiPulsa', '1234567890'
WHERE NOT EXISTS (SELECT 1 FROM public.banks WHERE bank_name = 'BCA');

INSERT INTO public.banks (bank_name, account_name, account_number)
SELECT 'DANA', 'MisiPulsa Official', '081234567890'
WHERE NOT EXISTS (SELECT 1 FROM public.banks WHERE bank_name = 'DANA');

-- ==========================================================================
-- 9. TABEL DEPOSITS (Top-up / deposit manual oleh admin + riwayat member)
-- ==========================================================================
CREATE TABLE IF NOT EXISTS public.deposits (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    user_name TEXT,
    amount TEXT NOT NULL,
    points INT DEFAULT 0,
    method TEXT,
    note TEXT,            -- Paket yang dibeli (mis. 'YouTube VIP') untuk transfer manual
    proof_image TEXT,     -- Bukti transfer (data URL JPEG terkompres, diupload member)
    status TEXT DEFAULT 'approved',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- Kolom bukti & paket (aman dijalankan ulang)
ALTER TABLE public.deposits ADD COLUMN IF NOT EXISTS note TEXT;
ALTER TABLE public.deposits ADD COLUMN IF NOT EXISTS proof_image TEXT;

ALTER TABLE public.deposits ENABLE ROW LEVEL SECURITY;

-- Member hanya melihat & membuat deposit miliknya; admin melihat & mengelola semua.
DROP POLICY IF EXISTS "Users can view own deposits." ON public.deposits;
CREATE POLICY "Users can view own deposits." ON public.deposits
    FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can insert own deposits." ON public.deposits;
CREATE POLICY "Users can insert own deposits." ON public.deposits
    FOR INSERT WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Admins can manage deposits" ON public.deposits;
CREATE POLICY "Admins can manage deposits" ON public.deposits
    FOR ALL USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());

-- ==========================================================================
-- 10. KOLOM USER_NAME DI WITHDRAWALS (untuk WD manual oleh admin)
-- ==========================================================================
ALTER TABLE public.withdrawals
    ADD COLUMN IF NOT EXISTS user_name TEXT;

-- Admin juga boleh membuat & menghapus penarikan (WD manual).
DROP POLICY IF EXISTS "Admins can insert withdrawals" ON public.withdrawals;
CREATE POLICY "Admins can insert withdrawals" ON public.withdrawals
    FOR INSERT WITH CHECK (public.is_admin_user());

DROP POLICY IF EXISTS "Admins can delete withdrawals" ON public.withdrawals;
CREATE POLICY "Admins can delete withdrawals" ON public.withdrawals
    FOR DELETE USING (public.is_admin_user());

-- ==========================================================================
-- 11. RPC ADMIN: KELOLA PROFIL (SECURITY DEFINER)
--     Kolom points/is_admin/referral_code TIDAK bisa diubah user langsung
--     (column grants), jadi semua mutasi profil oleh admin lewat fungsi ini.
-- ==========================================================================
CREATE OR REPLACE FUNCTION public.admin_update_profile(
    p_id UUID,
    p_full_name TEXT,
    p_phone TEXT,
    p_points INT,
    p_level TEXT,
    p_is_admin BOOLEAN,
    p_referral_code TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_row public.profiles%ROWTYPE;
BEGIN
    IF NOT public.is_admin_user() THEN
        RAISE EXCEPTION 'Hanya admin yang bisa mengubah user.';
    END IF;

    UPDATE public.profiles
       SET full_name     = COALESCE(p_full_name, full_name),
           phone         = COALESCE(p_phone, phone),
           points        = COALESCE(p_points, points),
           level         = COALESCE(p_level, level),
           is_admin      = COALESCE(p_is_admin, is_admin),
           referral_code = COALESCE(p_referral_code, referral_code)
     WHERE id = p_id
     RETURNING * INTO v_row;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'User tidak ditemukan.';
    END IF;

    RETURN to_jsonb(v_row);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.admin_update_profile(UUID, TEXT, TEXT, INT, TEXT, BOOLEAN, TEXT) FROM anon, public;
GRANT EXECUTE ON FUNCTION public.admin_update_profile(UUID, TEXT, TEXT, INT, TEXT, BOOLEAN, TEXT) TO authenticated;

CREATE OR REPLACE FUNCTION public.admin_create_profile(
    p_auth_id UUID,
    p_full_name TEXT,
    p_phone TEXT,
    p_points INT,
    p_level TEXT,
    p_is_admin BOOLEAN,
    p_referral_code TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_row public.profiles%ROWTYPE;
    v_code TEXT;
BEGIN
    IF NOT public.is_admin_user() THEN
        RAISE EXCEPTION 'Hanya admin yang bisa menambah user.';
    END IF;
    IF p_auth_id IS NULL THEN
        RAISE EXCEPTION 'Auth User ID wajib diisi (UUID user di Supabase Auth).';
    END IF;

    v_code := COALESCE(NULLIF(UPPER(TRIM(p_referral_code)), ''),
                       UPPER('MISI' || SUBSTRING(REPLACE(p_auth_id::text, '-', ''), 1, 6)));

    INSERT INTO public.profiles (id, full_name, phone, points, level, is_admin, referral_code)
    VALUES (
        p_auth_id,
        COALESCE(p_full_name, 'Member MisiPulsa'),
        p_phone,
        COALESCE(p_points, 100),
        COALESCE(p_level, 'Free'),
        COALESCE(p_is_admin, FALSE),
        v_code
    )
    RETURNING * INTO v_row;

    RETURN to_jsonb(v_row);
EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'Profil untuk auth user tersebut sudah ada.';
END;
$$;

REVOKE EXECUTE ON FUNCTION public.admin_create_profile(UUID, TEXT, TEXT, INT, TEXT, BOOLEAN, TEXT) FROM anon, public;
GRANT EXECUTE ON FUNCTION public.admin_create_profile(UUID, TEXT, TEXT, INT, TEXT, BOOLEAN, TEXT) TO authenticated;

CREATE OR REPLACE FUNCTION public.admin_delete_profile(p_id UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF NOT public.is_admin_user() THEN
        RAISE EXCEPTION 'Hanya admin yang bisa menghapus user.';
    END IF;
    IF p_id = auth.uid() THEN
        RAISE EXCEPTION 'Tidak bisa menghapus akun sendiri.';
    END IF;
    DELETE FROM public.profiles WHERE id = p_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.admin_delete_profile(UUID) FROM anon, public;
GRANT EXECUTE ON FUNCTION public.admin_delete_profile(UUID) TO authenticated;

-- ==========================================================================
-- 12. RPC ADMIN: KREDIT POIN (dipakai saat deposit manual disetujui)
-- ==========================================================================
CREATE OR REPLACE FUNCTION public.admin_credit_points(p_user_id UUID, p_points INT)
RETURNS INT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_new INT;
BEGIN
    IF NOT public.is_admin_user() THEN
        RAISE EXCEPTION 'Hanya admin yang bisa memberi poin.';
    END IF;
    IF p_points IS NULL OR p_points <= 0 THEN
        RAISE EXCEPTION 'Jumlah poin tidak valid.';
    END IF;

    UPDATE public.profiles
       SET points = COALESCE(points, 0) + p_points
     WHERE id = p_user_id
     RETURNING points INTO v_new;

    IF v_new IS NULL THEN
        RAISE EXCEPTION 'User tidak ditemukan.';
    END IF;
    RETURN v_new;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.admin_credit_points(UUID, INT) FROM anon, public;
GRANT EXECUTE ON FUNCTION public.admin_credit_points(UUID, INT) TO authenticated;
