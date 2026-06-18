"use server";

import { createClient } from "@/utils/supabase/server";

export async function loginAdmin(formData: FormData) {
  const email = formData.get("username") as string;
  const password = formData.get("password") as string;

  if (!email || !password) {
    return { success: false, error: "Email dan password wajib diisi." };
  }

  try {
    const supabase = await createClient();

    // 1. Autentikasi akun ke Supabase Auth
    const { data: authData, error: authError } =
      await supabase.auth.signInWithPassword({
        email,
        password,
      });

    if (authError) {
      return {
        success: false,
        error: "Kredensial salah atau akun tidak ditemukan.",
      };
    }

    // 2. Otorisasi: Periksa apakah user ID ini ada di tabel 'admins'
    const { data: adminData, error: adminError } = await supabase
      .from("admins")
      .select("role")
      .eq("id", authData.user.id)
      .single();

    if (adminError || !adminData) {
      await supabase.auth.signOut();
      return {
        success: false,
        error: "Akses ditolak. Anda bukan administrator resmi.",
      };
    }

    return { success: true, role: adminData.role };
  } catch (err) {
    console.error("Kesalahan sistem saat login admin:", err);
    return { success: false, error: "Terjadi kesalahan internal pada server." };
  }
}

/**
 * Server Action untuk memverifikasi PIN Pemilih (Token Voting)
 */
export async function verifyVoterPin(pin: string) {
  if (!pin || pin.trim() === "") {
    return { success: false, error: "PIN wajib diisi." };
  }

  try {
    const supabase = await createClient();

    // Cari data token berdasarkan PIN dan gabungkan (join) dengan tabel classes
    const { data: token, error } = await supabase
      .from("tokens")
      .select(`
        id,
        pin,
        is_used,
        classes (
          id,
          name
        )
      `)
      .eq("pin", pin.trim())
      .single();

    // Jika PIN tidak ditemukan di database
    if (error || !token) {
      return {
        success: false,
        error: "PIN tidak valid atau tidak terdaftar.",
      };
    }

    // Cek apakah token sudah digunakan sebelumnya
    if (token.is_used) {
      return {
        success: false,
        error: "Maaf, PIN ini sudah digunakan untuk melakukan voting.",
      };
    }

    // Jika valid, kembalikan data token
    return {
      success: true,
      data: {
        tokenId: token.id,
       className: token.classes?.[0]?.name ?? "Kelas tidak ditemukan", 
      },
    };
  } catch (err) {
    console.error("Kesalahan sistem saat verifikasi PIN:", err);
    return { success: false, error: "Terjadi kesalahan internal pada server." };
  }
}

/**
 * Server Action untuk Logout Admin
 */
export async function logoutAdmin() {
  try {
    const supabase = await createClient();
    await supabase.auth.signOut();
    return { success: true };
  } catch (err) {
    console.error("Kesalahan sistem saat logout:", err);
    return { success: false, error: "Gagal melakukan logout." };
  }
}