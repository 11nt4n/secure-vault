# -*- coding: utf-8 -*-
"""
Generator dokumen Analisis Kebutuhan Sistem Secure Vault (.docx)
Sumber: prd baru.pdf (9 halaman) — diselaraskan secara komprehensif
untuk kebutuhan Pusat Sertifikasi Teknologi Keamanan Siber dan Sandi (BSSN).
Output: Analisis_Kebutuhan_Sistem_Secure_Vault.docx
"""

import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

ORG = "Pusat Sertifikasi Teknologi Keamanan Siber dan Sandi"

C_NAVY = RGBColor(27, 54, 93)      # #1B365D
C_STEEL = RGBColor(43, 84, 126)    # #2B547E
C_DARK = RGBColor(40, 40, 40)      # #282828
C_MUTED = RGBColor(100, 100, 100)  # #646464
HEX_NAVY = "1B365D"
HEX_STEEL = "2B547E"
HEX_LIGHT_BG = "F4F7FA"
HEX_CALLOUT_BG = "F0F4F8"
HEX_BORDER = "C6D2DE"
FONT = "Arial"

L = WD_ALIGN_PARAGRAPH.LEFT
C = WD_ALIGN_PARAGRAPH.CENTER
J = WD_ALIGN_PARAGRAPH.JUSTIFY


def build(filename="Analisis_Kebutuhan_Sistem_Secure_Vault.docx"):
    doc = docx.Document()

    # 1. Page Margins & Header/Footer
    for s in doc.sections:
        s.top_margin = Inches(1.0)
        s.bottom_margin = Inches(1.0)
        s.left_margin = Inches(0.9)
        s.right_margin = Inches(0.9)

        hp = s.header.paragraphs[0]
        hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        r = hp.add_run("Secure Vault — Analisis Kebutuhan Sistem (PRD Baseline)")
        r.font.name, r.font.size, r.font.color.rgb = FONT, Pt(8.5), RGBColor(120, 120, 120)

        fp = s.footer.paragraphs[0]
        r = fp.add_run(f"Dokumen Analisis Sistem PKL | {ORG}")
        r.font.name, r.font.size, r.font.color.rgb = FONT, Pt(8.5), RGBColor(120, 120, 120)

    # ---------------- Helper Functions ----------------
    def run(p, text, size=9.5, bold=False, italic=False, color=C_DARK):
        r = p.add_run(text)
        r.font.name, r.font.size, r.bold, r.italic = FONT, Pt(size), bold, italic
        r.font.color.rgb = color
        return r

    def heading(text, size, color, before, after, align=L):
        p = doc.add_paragraph()
        p.alignment = align
        p.paragraph_format.space_before = Pt(before)
        p.paragraph_format.space_after = Pt(after)
        p.paragraph_format.keep_with_next = True
        run(p, text, size, bold=True, color=color)
        return p

    def title(t): heading(t, 18, C_NAVY, 12, 4, C)

    def subtitle(t):
        p = doc.add_paragraph()
        p.alignment = C
        p.paragraph_format.space_after = Pt(16)
        run(p, t, 11, color=C_STEEL)

    def h1(t): heading(t, 13, C_NAVY, 18, 6)
    def h2(t): heading(t, 11, C_STEEL, 13, 4)
    def h3(t): heading(t, 10, RGBColor(50, 50, 50), 9, 3)

    def body(text, prefix=""):
        p = doc.add_paragraph()
        p.alignment = J
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.line_spacing = 1.15
        if prefix:
            run(p, prefix, bold=True)
        run(p, text)

    def bullet(text, prefix="", level=0):
        p = doc.add_paragraph()
        p.alignment = J
        p.paragraph_format.space_after = Pt(2.5)
        p.paragraph_format.line_spacing = 1.15
        indent = 0.25 + (level * 0.2)
        p.paragraph_format.left_indent = Inches(indent)
        p.paragraph_format.first_line_indent = Inches(-0.15)
        run(p, "• " if level == 0 else "– ", bold=True, color=C_STEEL)
        if prefix:
            run(p, prefix, bold=True)
        run(p, text)

    def callout(text, head):
        t = doc.add_table(rows=1, cols=1)
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell = t.rows[0].cells[0]
        cell.width = Inches(6.7)
        tcPr = cell._tc.get_or_add_tcPr()
        tcPr.append(parse_xml(f'<w:shd {nsdecls("w")} w:fill="{HEX_CALLOUT_BG}"/>'))
        tcPr.append(parse_xml(
            f'<w:tcMar {nsdecls("w")}><w:top w:w="120" w:type="dxa"/><w:bottom w:w="120" w:type="dxa"/>'
            f'<w:left w:w="180" w:type="dxa"/><w:right w:w="180" w:type="dxa"/></w:tcMar>'))
        tcPr.append(parse_xml(
            f'<w:tcBorders {nsdecls("w")}><w:top w:val="none"/>'
            f'<w:left w:val="single" w:sz="24" w:space="0" w:color="{HEX_NAVY}"/>'
            f'<w:bottom w:val="none"/><w:right w:val="none"/></w:tcBorders>'))
        p = cell.paragraphs[0]
        run(p, f"■ {head}\n", 9.5, bold=True, color=C_NAVY)
        run(p, text, 9)
        doc.add_paragraph().paragraph_format.space_after = Pt(3)

    def table(widths, aligns, headers, rows):
        tbl = doc.add_table(rows=len(rows) + 1, cols=len(headers))
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        tbl._tbl.tblPr.append(parse_xml(
            f'<w:tblBorders {nsdecls("w")}>'
            f'<w:top w:val="single" w:sz="6" w:space="0" w:color="{HEX_NAVY}"/>'
            f'<w:bottom w:val="single" w:sz="6" w:space="0" w:color="{HEX_NAVY}"/>'
            f'<w:left w:val="single" w:sz="4" w:space="0" w:color="{HEX_BORDER}"/>'
            f'<w:right w:val="single" w:sz="4" w:space="0" w:color="{HEX_BORDER}"/>'
            f'<w:insideH w:val="single" w:sz="4" w:space="0" w:color="{HEX_BORDER}"/>'
            f'<w:insideV w:val="single" w:sz="4" w:space="0" w:color="{HEX_BORDER}"/>'
            f'</w:tblBorders>'))
        hdr = tbl.rows[0]
        hdr._tr.get_or_add_trPr().append(parse_xml(f'<w:tblHeader {nsdecls("w")}/>'))
        for i, h in enumerate(headers):
            cell = hdr.cells[i]
            cell.width = Inches(widths[i])
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            cell._tc.get_or_add_tcPr().append(parse_xml(f'<w:shd {nsdecls("w")} w:fill="{HEX_NAVY}"/>'))
            p = cell.paragraphs[0]
            p.alignment = aligns[i]
            run(p, h, 9, bold=True, color=RGBColor(255, 255, 255))
        for ri, row in enumerate(rows):
            r = tbl.rows[ri + 1]
            r._tr.get_or_add_trPr().append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))
            for ci, val in enumerate(row):
                cell = r.cells[ci]
                cell.width = Inches(widths[ci])
                if ri % 2 == 1:
                    cell._tc.get_or_add_tcPr().append(
                        parse_xml(f'<w:shd {nsdecls("w")} w:fill="{HEX_LIGHT_BG}"/>'))
                for li, line in enumerate(str(val).split("\n")):
                    p = cell.paragraphs[0] if li == 0 else cell.add_paragraph()
                    p.alignment = aligns[ci]
                    p.paragraph_format.space_after = Pt(1)
                    p.paragraph_format.line_spacing = 1.15
                    if line.startswith("• "):
                        run(p, "• ", 8.5, bold=True, color=C_STEEL)
                        line = line[2:]
                    bold_cell = (headers[1] == "User" and ci == 1 and li == 0)
                    run(p, line, 8.5, bold=bold_cell)
        doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # =========================================================
    # DOKUMEN UTAMA
    # =========================================================
    title("ANALISIS KEBUTUHAN SISTEM SECURE VAULT")
    subtitle(f"Aplikasi Penyimpanan Berkas Terenkripsi Berbasis Zero-Knowledge & Envelope Encryption 3 Lapis\nKonteks: {ORG}")

    callout(
        "Secure Vault adalah aplikasi web penyimpanan berkas berbasis Zero-Knowledge. "
        "Berkas dienkripsi di peramban menggunakan AES-256-GCM melalui skema Envelope Encryption 3 Lapis "
        "(Passphrase → KEK → Master Key → DEK) sebelum dikirimkan ke server, sehingga administrator maupun "
        "pihak infrastruktur tidak pernah melihat teks-asli (plaintext) dokumen maupun kunci kriptografinya.\n\n"
        f"Dalam konteks {ORG}, Secure Vault diposisikan sebagai sarana brankas penyimpanan berkas-berkas "
        "krusial terkait proses sertifikasi dan evaluasi keamanan teknologi siber dan sandi negara. "
        "Arsitektur dan spesifikasi keamanan Secure Vault dirancang mengacu pada standar internasional "
        "ISO/IEC 15408:2022 (Common Criteria) dengan target kepatuhan ISO/IEC 15408-2 dan 15408-3 (NFR-05).",
        "RINGKASAN EKSEKUTIF"
    )

    # ---------------- A. PENGGUNA SECURE VAULT ----------------
    h1("A. PENGGUNA SECURE VAULT")
    body(
        "Secure Vault dibangun untuk 2 (dua) pengguna, yaitu Administrator dan Pengguna (User). "
        "Pemisahan peran ini dikelola secara terpusat melalui Role-Based Access Control (RBAC) pada Keycloak "
        "dengan menjunjung tinggi prinsip Least Privilege (hak akses minimum): Administrator mengelola sistem "
        "dan kebijakan operasional, bukan isi brankas (vault), dan tidak ada peran apa pun di dalam sistem yang "
        "dapat membaca atau mengakses berkas milik pengguna lain."
    )
    bullet(
        f"Personel yang bertanggung jawab atas tata kelola administratif dan pemeliharaan operasional sistem Secure Vault "
        f"di lingkungan {ORG}. Administrator berwenang mengelola akun pengguna, menetapkan alokasi kuota penyimpanan, "
        "menegakkan kebijakan autentikasi (MFA dan kata sandi), memantau telemetri keamanan dan jejak audit secara hanya-baca (read-only), "
        "serta mencabut sesi aktif jika terindikasi ancaman keamanan.",
        "1. Administrator: "
    )
    bullet(
        f"Personel di lingkungan {ORG} (seperti pejabat fungsional sandiman, evaluator keamanan perangkat lunak/keras, "
        "analis laboratorium uji keamanan siber, tim penjamin mutu sertifikasi, dan staf sekretariat sertifikasi) yang "
        "memerlukan sarana penyimpanan terisolasi untuk mengamankan berkas-berkas rahasia dalam brankas pribadi masing-masing "
        "(misalnya: dokumen permohonan sertifikasi, laporan hasil evaluasi kerentanan, Security Target / TOE, kunci kriptografi, "
        "dan kode sumber/firmware produk yang diuji).",
        "2. Pengguna (User): "
    )

    # ---------------- B. ANALISIS SISTEM ----------------
    h1("B. ANALISIS SISTEM")

    # B.1. Analisis Kebutuhan Fungsional
    h2("B.1. Analisis Kebutuhan Fungsional")
    body(
        "Analisis ini berisi fungsi-fungsi apa saja yang dapat dilakukan oleh setiap pengguna pada sistem informasi. "
        "Berikut adalah kebutuhan fungsional pada sistem Secure Vault:"
    )

    # Tabel Peran / Fungsi
    table([0.5, 1.6, 4.6], [C, L, L], ["No", "User", "Peran/Fungsi"], [
        ["1.", "Administrator",
         "• Mengelola akun pengguna (membuat, menonaktifkan, dan menghapus akun pengguna via Keycloak)\n"
         "• Mengatur kuota penyimpanan per pengguna dan batas ukuran berkas maksimal (500 MB per file pada rilis MVP)\n"
         "• Menegakkan kebijakan keamanan login (kewajiban MFA berbasis TOTP dan kompleksitas password)\n"
         "• Melihat jejak audit (audit trail) seluruh sistem secara hanya-baca (read-only)\n"
         "• Memantau kondisi dan dasbor keamanan sistem (termasuk deteksi brute-force dan pemantauan kapasitas)\n"
         "• Memantau dan mencabut sesi aktif pengguna secara instan bila terindikasi anomali\n"
         "Batasan Mutlak: Administrator TIDAK BISA membaca, mengunduh, atau mendekripsi berkas pengguna; "
         "TIDAK BISA mengakses passphrase, KEK, maupun Master Key pengguna; serta TIDAK BISA memodifikasi atau menghapus log audit."],
        ["2.", "Pengguna (User)",
         "• Membuat vault pribadi dengan passphrase rahasia mandiri (menghasilkan KEK untuk membuka Master Key)\n"
         "• Mengenkripsi dan mengunggah berkas secara chunked (5 MB per potongan) menggunakan AES-256-GCM + AAD\n"
         "• Mengunduh, mendekripsi, dan memverifikasi integritas berkas secara lokal di peramban\n"
         "• Mengganti nama berkas, mengelompokkan berkas dengan label/tag virtual terenkripsi (flat-list), dan menghapus berkas miliknya sendiri secara aman\n"
         "• Melihat riwayat aktivitas (audit log) pada akun miliknya sendiri\n"
         "• Mengelola perangkat autentikasi MFA mandiri dan mengganti passphrase vault (melakukan re-wrap pada 1 Master Key menggunakan KEK baru tanpa re-enkripsi berkas)\n"
         "Batasan Mutlak: Pengguna TIDAK BISA mengakses berkas atau log milik pengguna lain, tidak dapat mengakses endpoint admin, "
         "dan bertanggung jawab penuh menjaga passphrase (jika passphrase hilang, data tidak dapat dipulihkan oleh siapa pun/by design)."],
    ])

    # Tabel Rincian FR-01 sampai FR-16
    h3("Rincian Spesifikasi Kebutuhan Fungsional (FR-01 s/d FR-16 Sesuai PRD Baru)")
    body(
        "Kebutuhan fungsional sistem diklasifikasikan ke dalam 3 kapabilitas teknis utama serta dipetakan berdasarkan tingkat "
        "urgensi rilis MVP: P0 = Must-Have (wajib selesai dalam sprint 35 hari); P1/P2 = Nice-to-Have (backlog minggu ke-4 / pasca-MVP):"
    )

    fr_headers = ["Kapabilitas Inti", "Kode", "Spesifikasi Kebutuhan Fungsional", "Prioritas", "Kriteria Penerimaan (Acceptance Criteria)"]
    fr_widths = [1.2, 0.6, 2.7, 0.7, 1.5]
    fr_aligns = [L, C, L, C, L]

    fr_data = [
        ["Enkripsi Sisi Klien", "FR-01", "Turunkan KEK dari passphrase dengan Argon2id via argon2-browser (WASM) di Web Worker (m=64 MiB, t=3, p=1, salt 16 byte unik); gunakan KEK untuk membuka Master Key (MK) 256-bit dan impor ke Web Crypto API sebagai kunci non-extractable. Validasi login vault menggunakan encrypted verifier string.", "P0", "Inspeksi trafik & database bebas dari plaintext/kunci mentah; derivasi Argon2id < 2 detik tanpa UI freeze."],
        ["Enkripsi Sisi Klien", "FR-02", "Buat 1 Data Encryption Key (DEK) 256-bit acak per file (dipakai konsisten untuk seluruh chunk pada file tersebut).", "P0", "DEK digenerate via CSPRNG dan unik untuk setiap file."],
        ["Enkripsi Sisi Klien", "FR-03", "Hasilkan IV 96-bit unik per chunk disertai Additional Authenticated Data (AAD) berupa kombinasi (file_id + chunk_index) untuk mencegah penukaran urutan chunk.", "P0", "Manipulasi urutan chunk terdeteksi dan ditolak oleh Web Crypto API."],
        ["Enkripsi Sisi Klien", "FR-04", "MK dibungkus oleh KEK, dan DEK dibungkus oleh MK menggunakan algoritma AES Key Wrap (AES-KW) sebelum dikirim ke server.", "P0", "Kunci mentah tidak pernah melintasi jaringan dalam bentuk plaintext."],
        ["Enkripsi Sisi Klien", "FR-05", "KEK, MK, dan DEK hanya disimpan di RAM browser (non-extractable) dan segera dihapus (set to null) saat logout atau sesi 15 menit berakhir.", "P0", "Zero-memory footprint setelah logout atau timeout tercapai."],
        ["Unggah / Unduh File", "FR-06", "Unggah dan unduh chunked (5 MB per chunk), tiap chunk dienkripsi/didekripsi terpisah dengan AES-256-GCM + AAD.", "P0", "File 100 MB terunggah dan terunduh utuh dengan enkripsi < 5 detik."],
        ["Unggah / Unduh File", "FR-07", "Mendukung mekanisme resume unggahan yang terputus di tengah jalan tanpa mengulang dari chunk pertama.", "P1", "Unggahan dapat dilanjutkan secara transparan setelah koneksi pulih."],
        ["Unggah / Unduh File", "FR-08", "Membatasi ukuran berkas maksimal 500 MB (rilis MVP) dan pengaturan kuota penyimpanan per akun pengguna.", "P0", "Penolakan otomatis jika berkas melebihi 500 MB atau kuota storage habis."],
        ["Unggah / Unduh File", "FR-09", "Unduh chunk lalu dekripsi dan verifikasi authentication tag GCM serta penguncian AAD di peramban.", "P0", "Berkas terdekripsi identik dengan berkas asli (hash SHA-256 cocok)."],
        ["Unggah / Unduh File", "FR-10", "Kegagalan dekripsi atau ketidakcocokan urutan AAD memicu peringatan integritas dan membatalkan perakitan file.", "P0", "Ciphertext yang rusak/tertukar langsung dibatalkan prosesnya."],
        ["Unggah / Unduh File", "FR-11", "Pengelompokan file flat-list menggunakan label/tag terenkripsi, serta hapus file secara aman (ciphertext chunk dan wrapped DEK).", "P0", "Ciphertext dan metadata terhapus tuntas dari storage dan DB."],
        ["Audit Trail", "FR-12", "Catat kejadian: login berhasil, gagal login, unggah, unduh, hapus, ganti passphrase (re-wrap MK), dan seluruh aksi admin.", "P0", "100% kejadian krusial tercatat ke dalam audit trail."],
        ["Audit Trail", "FR-13", "Setiap entri log wajib memuat: timestamp (NTP), user ID, aksi, file ID, IP, user agent, hasil, previous_hash, dan current_hash.", "P0", "Kelengkapan atribut data audit terpenuhi dalam format JSON."],
        ["Audit Trail", "FR-14", "Hash-chain SHA-256 antar entri di PostgreSQL menggunakan transaksi row-level locking (SELECT FOR UPDATE) untuk mendeteksi manipulasi dan mencegah forking.", "P0", "Pencatatan audit < 1 detik tanpa race condition; manipulasi terdeteksi."],
        ["Audit Trail", "FR-15", "Pengiriman log audit secara asinkron via Filebeat ke ELK Stack dan korelasi alert keamanan pada Wazuh SIEM.", "P1/P2", "Log terindeks di Kibana secara asinkron tanpa membebani transaksi DB."],
        ["Audit Trail", "FR-16", "Endpoint API dan dasbor filter audit log (read-only) berdasarkan user, jenis aksi, dan rentang waktu.", "P0", "Pencarian dan peninjauan riwayat log audit responsif dan akurat."]
    ]
    table(fr_widths, fr_aligns, fr_headers, fr_data)

    # ---------------- B.2. ANALISIS KEBUTUHAN NON-FUNGSIONAL ----------------
    h2("B.2. Analisis Kebutuhan Non-Fungsional")
    body("Kebutuhan non-fungsional merupakan kebutuhan pendukung sistem, yang terdiri dari:")
    bullet("Aspek perlindungan kerahasiaan data (Zero-Knowledge 3 lapis), keaslian data (AAD), integritas memori, otentikasi Zero-Trust, prinsip Least Privilege, audit trail zero-forking, dan pengerasan aplikasi.", "a) Kebutuhan Keamanan: ")
    bullet("Infrastruktur fisik server on-premise Pusat Sertifikasi, redundansi media penyimpanan RAID 10/1, fasilitas cadangan offline, spesifikasi perangkat klien, dan token fisik WebAuthn.", "b) Operasional Hardware: ")
    bullet("Perangkat lunak Target of Evaluation (TOE) seperti frontend React TS, backend Node.js TS, Web Crypto API/WASM; serta Lingkungan Operasional (OE) seperti PostgreSQL 16, Nginx, Keycloak IAM, dan Docker Compose.", "c) Operasional Software: ")
    bullet("Kebutuhan informasi identitas pengguna, metadata berkas flat-list, informasi kriptografis terikat, atribut audit log, serta telemetri peringatan integritas berkas.", "d) Kebutuhan Informasi: ")
    bullet("Kebutuhan antarmuka login SSO & MFA, inisialisasi/buka vault dengan verifier string, dasbor flat-list berkas, komponen unggah/unduh interaktif (zero UI freeze), konsol admin, dan log viewer.", "e) Kebutuhan Tampilan: ")

    body(
        "Berikut adalah tabulasi komprehensif analisis kebutuhan non-fungsional sistem Secure Vault "
        "yang diturunkan secara langsung dari dokumen PRD Baru (Halaman 2, 3, 4, 6, dan 9):"
    )

    # Tabel Master Kebutuhan Non-Fungsional
    nfr_master_headers = ["No", "Kategori Kebutuhan", "Aspek / Parameter Kebutuhan", "Spesifikasi Teknis & Standar Acuan (PRD Baru)"]
    nfr_master_widths = [0.4, 1.4, 2.0, 2.9]
    nfr_master_aligns = [C, L, L, L]

    nfr_master_rows = [
        # a) Kebutuhan Keamanan
        ["1.", "a) Kebutuhan Keamanan", "Arsitektur Zero-Knowledge & Envelope Encryption 3 Lapis",
         "Sistem menerapkan hierarki kunci 3 lapis (Passphrase → KEK → Master Key → DEK). KEK diturunkan di browser dengan Argon2id WASM (m=64 MiB, t=3, p=1, salt 16-byte unik). KEK membungkus Master Key 256-bit via AES-KW. Server hanya menyimpan encrypted verifier string untuk validasi login vault tanpa pernah melihat passphrase atau Master Key."],
        ["2.", "a) Kebutuhan Keamanan", "Integritas Berkas & Penguncian AAD",
         "Enkripsi berkas menggunakan AES-256-GCM dengan potongan (chunk) 5 MB. Setiap chunk memiliki IV 96-bit unik dan Additional Authenticated Data (AAD) berupa (file_id + chunk_index). Penukaran urutan chunk di server/transit langsung ditolak oleh Web Crypto API."],
        ["3.", "a) Kebutuhan Keamanan", "Keamanan Kunci di RAM Klien (Zero-Leakage)",
         "Kunci KEK, Master Key, dan DEK diimpor sebagai objek CryptoKey non-extractable di Web Crypto API, hanya tersimpan di RAM browser selama sesi aktif, tidak pernah ditulis ke LocalStorage/disk, dan langsung dihapus (set to null) saat logout atau sesi 15 menit berakhir."],
        ["4.", "a) Kebutuhan Keamanan", "Prinsip Zero-Trust & Manajemen Sesi",
         "Setiap request API divalidasi token JWT dari Keycloak (signature, expiry, audience). MFA wajib berbasis TOTP untuk seluruh akun. Sesi dibatasi 15 menit dengan rotasi refresh token. Seluruh jalur komunikasi wajib TLS 1.3 dan mTLS internal. DB & storage tidak diekspos publik."],
        ["5.", "a) Kebutuhan Keamanan", "Prinsip Least Privilege & Pemisahan Peran",
         "Pemisahan peran tegas antara Admin dan User pada Keycloak. Service account per komponen memiliki izin sempit. Akun DB PostgreSQL aplikasi tanpa hak DDL. Akses audit trail bersifat hanya-baca (read-only) dan terpisah dari admin aplikasi."],
        ["6.", "a) Kebutuhan Keamanan", "Audit Trail Anti-Repudiasi (Zero-Forking)",
         "Pencatatan riwayat audit berantai (SHA-256 hash-chain) ke PostgreSQL dengan row-level locking (SELECT FOR UPDATE) untuk mencegah race condition/forking dan menjamin anti-repudiasi mutlak."],
        ["7.", "a) Kebutuhan Keamanan", "Pengerasan Aplikasi & Mitigasi STRIDE",
         "Brute-force lockout Keycloak, Content Security Policy (CSP) ketat tanpa unsafe-inline, Subresource Integrity (SRI) modul WASM, otorisasi kepemilikan objek (owner_id == user_id), UUID v4 acak non-sequential (cegah IDOR), dan rate limiting per IP/user di Nginx."],
        ["8.", "a) Kebutuhan Keamanan", "Kesesuaian Standar Keamanan Internasional (NFR-05)",
         f"Arsitektur dan spesifikasi keamanan dirancang mengacu pada standar evaluasi ISO/IEC 15408:2022 (Common Criteria) dengan target kepatuhan ISO/IEC 15408-2 (SFR) dan ISO/IEC 15408-3 (SAR), selaras dengan tugas pokok {ORG}."],

        # b) Operasional Hardware
        ["9.", "b) Operasional Hardware", "Infrastruktur Server On-Premise",
         f"Seluruh stack sistem di-host on-premise pada server pusat data milik {ORG} tanpa ketergantungan cloud pihak ketiga asing. Pada tahap MVP, sistem di-deploy di atas Virtual Machine (VM) Ubuntu Server."],
        ["10.", "b) Operasional Hardware", "Redundansi Penyimpanan (RAID Storage)",
         "Penyimpanan ciphertext (NAS lokal) wajib menggunakan RAID 10 untuk data ciphertext (throughput tinggi dan toleransi multi-disk failure) serta RAID 1 untuk partisi sistem operasi (OS), dilengkapi pemantauan S.M.A.R.T."],
        ["11.", "b) Operasional Hardware", "Fasilitas Pencadangan Offline",
         "Pencadangan data berkala yang diisolasi secara fisik dan logis (cold backup / air-gapped periodic backup) untuk kesiapsiagaan pemulihan bencana (disaster recovery)."],
        ["12.", "b) Operasional Hardware", "Spesifikasi Perangkat Klien",
         "Komputer/laptop personel klien minimal prosesor dual-core dengan RAM 4 GB (disarankan 8 GB ke atas) agar komputasi Argon2id (64 MiB RAM) dan pemrosesan chunk 5 MB di browser berjalan lancar tanpa freeze."],
        ["13.", "b) Operasional Hardware", "Token Keamanan Fisik (Backlog P1/P2)",
         "Dukungan kunci keamanan fisik berbasis WebAuthn (YubiKey hardware token) disiapkan khusus untuk akun Administrator guna mitigasi serangan pengambilalihan akun secara mutlak."],

        # c) Operasional Software
        ["14.", "c) Operasional Software", "Frontend Klien (Di dalam TOE)",
         "React (Vite) + TypeScript bertindak sebagai Single Page Application (SPA) antarmuka brankas berkas, orkestrasi Web Worker kripto, pengelolaan chunking 5 MB, dan manajemen state kunci RAM non-extractable."],
        ["15.", "c) Operasional Software", "Backend API Server (Di dalam TOE)",
         "Node.js (Express/Fastify) + TypeScript menangani validasi token JWT Zero-Trust, otorisasi kepemilikan file (owner_id == user_id), penanganan stream chunking, serta komputasi SHA-256 hash-chain audit log."],
        ["16.", "c) Operasional Software", "Mesin Kriptografi Sisi Klien (Di dalam TOE)",
         "W3C Web Crypto API (SubtleCrypto) untuk AES-256-GCM/AES-KW dan pustaka argon2-browser (Argon2id WASM) yang di-host lokal dengan pengamanan Subresource Integrity (SRI)."],
        ["17.", "c) Operasional Software", "Basis Data & Reverse Proxy (Lingkungan OE)",
         "PostgreSQL 16 mengelola metadata terenkripsi dan tabel append-only audit log dengan akun non-DDL. Nginx bertindak sebagai reverse proxy dengan terminasi TLS 1.3 eksklusif, HSTS, CSP ketat, dan rate limiting."],
        ["18.", "c) Operasional Software", "Identity & Access Management (Lingkungan OE)",
         "Keycloak On-Premise mengelola realm khusus Secure Vault, SSO berbasis OIDC dengan PKCE, penegakan MFA TOTP, dan brute-force detection."],
        ["19.", "c) Operasional Software", "Platform Deployment (Lingkungan OE)",
         "Docker Compose di atas VM Ubuntu Server on-premise untuk orkestrasi kontainer layanan secara terisolasi."],
        ["20.", "c) Operasional Software", "Observabilitas & SIEM (Lingkungan OE — Backlog P1/P2)",
         "ELK Stack (Filebeat, Logstash, Elasticsearch, Kibana) untuk visualisasi audit log; Wazuh Server & Agent untuk File Integrity Monitoring (FIM) dan Host Intrusion Detection."],

        # d) Kebutuhan Informasi
        ["21.", "d) Kebutuhan Informasi", "Informasi Profil & Akun Pengguna",
         "User ID (UUID v4), username, email korporat, role RBAC (Admin/User), status akun aktif, status aktivasi MFA, alokasi kuota penyimpanan, dan kuota terpakai."],
        ["22.", "d) Kebutuhan Informasi", "Informasi Berkas Terkelola",
         "File ID (UUID v4), nama berkas terenkripsi (didekripsi di peramban), label/tag virtual terenkripsi (flat-list), ukuran berkas ciphertext, hash integritas SHA-256, dan timestamp unggah/modifikasi."],
        ["23.", "d) Kebutuhan Informasi", "Informasi Kriptografis Terikat",
         "Salt KEK Argon2id (16-byte unik), encrypted verifier string, Master Key terbungkus KEK, DEK terbungkus MK, IV 96-bit per chunk, dan AAD (file_id + chunk_index). Plaintext dan passphrase TIDAK PERNAH menjadi informasi di server."],
        ["24.", "d) Kebutuhan Informasi", "Informasi Jejak Audit Terstruktur",
         "Timestamp presisi NTP, user ID terverifikasi, jenis aksi/event, file ID target, source IP, user agent, status operasi (SUCCESS/FAILED), previous_hash, dan current_hash."],
        ["25.", "d) Kebutuhan Informasi", "Informasi Peringatan & Telemetri Keamanan",
         "Notifikasi kegagalan verifikasi authentication tag GCM atau ketidakcocokan AAD (indikasi perusakan data), notifikasi lockout brute-force login, dan alert integritas berkas sistem dari Wazuh FIM."],

        # e) Kebutuhan Tampilan
        ["26.", "e) Kebutuhan Tampilan", "Tampilan Autentikasi & Verifikasi MFA",
         "Halaman login SSO Keycloak responsif dan bersih dengan formulir kredensial serta langkah verifikasi MFA berbasis kode TOTP."],
        ["27.", "e) Kebutuhan Tampilan", "Tampilan Inisialisasi & Buka Kunci Vault",
         "Dialog input passphrase dengan meteran kekuatan kata sandi, validasi encrypted verifier string, dan peringatan keras: 'Passphrase tidak disimpan di server. Kehilangan passphrase mengakibatkan berkas hilang permanen!'."],
        ["28.", "e) Kebutuhan Tampilan", "Tampilan Dasbor Berkas Flat-List",
         "Tabel daftar berkas modern dengan pengelompokan label/tag virtual terenkripsi, tombol aksi (Unggah, Unduh, Ganti Nama, Hapus), dan visualisasi progress bar kapasitas kuota penyimpanan."],
        ["29.", "e) Kebutuhan Tampilan", "Komponen Unggah & Unduh (Zero UI Freeze)",
         "Area drag-and-drop dengan indikator progres bertahap (enkripsi browser, chunking 5 MB, pengunggahan server) yang dieksekusi di Web Worker tanpa membekukan antarmuka pengguna."],
        ["30.", "e) Kebutuhan Tampilan", "Dasbor Manajemen Administrator",
         "Antarmuka konsol admin untuk manajemen akun user, konfigurasi kuota storage, penegakan kebijakan keamanan, dan tombol pencabutan sesi pengguna aktif secara seketika."],
        ["31.", "e) Kebutuhan Tampilan", "Dasbor Penampil Log Audit (Read-Only)",
         "Tabel audit log komprehensif dengan fitur filter dinamis berdasarkan identitas user, jenis aksi, status keberhasilan, dan rentang tanggal."]
    ]
    table(nfr_master_widths, nfr_master_aligns, nfr_master_headers, nfr_master_rows)

    # Tabel Target Kinerja Kualitas NFR-01 s/d NFR-05
    h3("Target Kualitas Sistem & Kinerja (NFR-01 s/d NFR-05 Berdasarkan PRD Baru)")
    body(
        "Tabel berikut merangkum target kuantitatif dan ambang batas kinerja teknis yang wajib dipenuhi "
        "oleh Secure Vault sesuai dokumen PRD Baru (Halaman 9):"
    )
    nfr_headers = ["Kode", "Dimensi Kualitas", "Spesifikasi Ambang Batas Kinerja & Keamanan", "Metode Verifikasi"]
    nfr_widths = [0.8, 1.8, 3.0, 1.1]
    nfr_aligns = [C, L, L, L]

    nfr_data = [
        ["NFR-01", "Kinerja Kriptografi", "Waktu derivasi KEK via Argon2id WASM di Web Worker wajib selesai < 2 detik. Waktu enkripsi file 100 MB selesai < 5 detik tanpa memblokir main thread UI (zero UI freeze).", "Benchmark pengujian performa browser"],
        ["NFR-02", "Kapasitas & Memori", "Ukuran maksimal berkas untuk rilis MVP dibatasi hingga 500 MB dengan pemrosesan streaming per chunk 5 MB untuk menjaga stabilitas memori peramban.", "Uji beban berkas batas 500 MB"],
        ["NFR-03", "Keamanan Sesi & Transport", "Seluruh jalur komunikasi wajib TLS 1.3, header CSP ketat tanpa unsafe-inline, serta penghapusan otomatis sesi JWT dan kunci di RAM setelah 15 menit idle.", "Security headers audit & idle test"],
        ["NFR-04", "Keandalan & Integritas Audit", "Penulisan audit log berantai (hash-chain) ke PostgreSQL wajib selesai < 1 detik dengan jaminan konsistensi sekuensial (zero-forking) melalui row-level locking.", "Uji konkurensi database PostgreSQL"],
        ["NFR-05", "Kesesuaian Standar Keamanan", "Arsitektur dan spesifikasi keamanan dirancang mengacu pada standar evaluasi ISO/IEC 15408:2022 (Common Criteria) dengan klaim konformansi ISO/IEC 15408-2 dan 15408-3.", "Pemetaan SFR/SAR Common Criteria"]
    ]
    table(nfr_widths, nfr_aligns, nfr_headers, nfr_data)

    # Tabel Matriks Prioritas MVP (P0 vs P1/P2)
    h3("Matriks Prioritas Kebutuhan MVP 35 Hari (PRD Baru Halaman 9)")
    body(
        "Tabel berikut memetakan prioritas implementasi fitur antara kebutuhan inti rilis MVP 35 hari "
        "dan kebutuhan yang dialokasikan ke backlog pengembangan:"
    )
    prio_headers = ["Tingkat Prioritas", "Kategori Fitur", "Rincian Kebutuhan Implementasi"]
    prio_widths = [1.4, 1.5, 3.8]
    prio_aligns = [C, L, L]

    prio_data = [
        ["Must-Have (P0)\nCore MVP 35 Hari", "Autentikasi & IAM", "Integrasi SSO Keycloak OIDC (PKCE) + kewajiban Multi-Factor Authentication berbasis TOTP."],
        ["Must-Have (P0)\nCore MVP 35 Hari", "Derivasi Kunci", "Derivasi KEK menggunakan Argon2id WASM di dalam Web Worker browser (m=64 MiB, t=3, p=1)."],
        ["Must-Have (P0)\nCore MVP 35 Hari", "Manajemen Kunci", "Arsitektur Envelope Encryption 3 Lapis (Passphrase → KEK → MK → DEK) + fitur ganti passphrase (re-wrap MK) & encrypted verifier string."],
        ["Must-Have (P0)\nCore MVP 35 Hari", "Operasi Berkas", "Upload & download chunked 5 MB dengan AES-256-GCM + penguncian AAD (file_id + chunk_index), batas ukuran berkas 500 MB."],
        ["Must-Have (P0)\nCore MVP 35 Hari", "Struktur Berkas", "Manajemen berkas flat-list dengan enkripsi nama berkas dan label/tag virtual terenkripsi."],
        ["Must-Have (P0)\nCore MVP 35 Hari", "Integritas Audit", "Audit trail append-only dengan SHA-256 hash-chain dan SELECT FOR UPDATE di database PostgreSQL."],
        ["Must-Have (P0)\nCore MVP 35 Hari", "Lingkungan Host", "Deployment terisolasi menggunakan simulasi Docker Compose di atas VM Ubuntu Server on-premise."],
        ["Nice-to-Have (P1/P2)\nBacklog Pasca-MVP", "Konektivitas Berkas", "Fitur resume unggahan chunk yang terputus di tengah jalan (FR-07)."],
        ["Nice-to-Have (P1/P2)\nBacklog Pasca-MVP", "Observabilitas Log", "Integrasi pipeline log asinkron Filebeat → Logstash → Elasticsearch → Kibana (ELK Stack) (FR-15)."],
        ["Nice-to-Have (P1/P2)\nBacklog Pasca-MVP", "Deteksi Intrusi Host", "Integrasi agen SIEM Wazuh untuk File Integrity Monitoring (FIM) dan korelasi alert host server."],
        ["Nice-to-Have (P1/P2)\nBacklog Pasca-MVP", "Autentikasi Fisik", "Penggunaan perangkat keras WebAuthn fisik (YubiKey hardware token) khusus untuk akun Administrator."]
    ]
    table(prio_widths, prio_aligns, prio_headers, prio_data)

    # ---------------- C. ANALISIS KEBUTUHAN DATA ----------------
    h1("C. ANALISIS KEBUTUHAN DATA")
    body(
        "Mengingat Secure Vault merupakan sistem brankas penyimpanan berkas berbasis Zero-Knowledge, sistem memisahkan "
        "secara mutlak antara Data Sisi Server (Server-Side Storage) yang tidak pernah memuat informasi sensitif dalam bentuk terbuka, "
        "dan Data Sisi Klien (Client-Side Transient Data) yang hanya hidup sementara di memori RAM browser pengguna:"
    )

    data_headers = ["Entitas Data", "Atribut / Field Data Kunci", "Tipe & Format", "Lokasi Penyimpanan", "Karakteristik & Kebijakan Keamanan"]
    data_widths = [1.3, 1.8, 0.9, 1.2, 1.5]
    data_aligns = [L, L, L, L, L]

    data_rows = [
        [
            "1. Pengguna & Identitas (User Account)",
            "• user_id (PK)\n• username\n• email\n• password_hash\n• mfa_totp_secret\n• role (Admin / User)\n• is_active\n• storage_quota_bytes\n• storage_used_bytes",
            "UUID v4\nString\nEmail format\nArgon2 / Bcrypt\nBase32 / String\nEnum\nBoolean\nBigInt\nBigInt",
            "Keycloak Database & PostgreSQL",
            "Kredensial login ter-hash searah. Role terpisah tegas. Akun DB aplikasi beroperasi tanpa hak DDL."
        ],
        [
            "2. Profil Kriptografi Vault (Vault Profile)",
            "• vault_id (PK)\n• user_id (FK)\n• kek_salt (16-byte unik)\n• encrypted_verifier_string\n• wrapped_master_key (by KEK)\n• argon2_params (m=64M, t=3, p=1)\n• last_rekey_timestamp",
            "UUID v4\nUUID v4\nBinary / Base64\nBinary (Ciphertext)\nBinary (AES-KW)\nJSON / Columns\nTimestamp",
            "Database Aplikasi (PostgreSQL)",
            "Menyimpan parameter publik dan kunci terbungkus. Passphrase dan KEK/MK mentah TIDAK PERNAH tersimpan di server."
        ],
        [
            "3. Metadata Berkas (Encrypted File Metadata)",
            "• file_id (PK)\n• vault_id (FK)\n• owner_user_id\n• encrypted_filename\n• encrypted_tags (flat-list)\n• wrapped_dek (by MK)\n• total_chunks\n• file_size_bytes\n• sha256_checksum",
            "UUID v4\nUUID v4\nUUID v4\nBase64 (Ciphertext)\nJSON Terenkripsi\nBinary (AES-KW)\nInteger\nBigInt\nString (64 hex)",
            "Database Aplikasi (PostgreSQL)",
            "Nama berkas dan label/tag dienkripsi di browser (Zero-Knowledge Metadata). Wrapped DEK dibungkus oleh Master Key."
        ],
        [
            "4. Potongan Berkas (Ciphertext File Chunks)",
            "• chunk_id (PK)\n• file_id (FK)\n• chunk_index (0..N)\n• chunk_size_bytes (<= 5 MB)\n• iv_nonce (96-bit unik)\n• gcm_auth_tag (128-bit)\n• aad_data (file_id + index)\n• ciphertext_payload",
            "UUID v4\nUUID v4\nInteger\nInteger\nBinary (12 byte)\nBinary (16 byte)\nString Terikat\nBinary Blob / File",
            "Storage NAS Lokal (RAID 10) / PostgreSQL",
            "Setiap potongan 5 MB dienkripsi dengan DEK unik, IV unik, dan AAD terikat. GCM tag wajib divalidasi saat perakitan unduhan."
        ],
        [
            "5. Jejak Audit Berantai (Hash-Chain Audit Log)",
            "• log_id (PK)\n• timestamp_utc (NTP)\n• event_type\n• actor_user_id\n• target_resource_id\n• source_ip\n• user_agent\n• event_status (OK/FAIL)\n• previous_hash\n• current_hash",
            "UUID v4\nTimestamp (NTP)\nString (Enum)\nUUID v4\nUUID v4 / String\nString (IP)\nString\nEnum\nString (SHA-256)\nString (SHA-256)",
            "PostgreSQL (Append-Only Table) & ELK Stack",
            "Tabel append-only. Setiap entri merantai hash entri sebelumnya (hash-chaining). Transaksi row-level locking mencegah forking."
        ],
        [
            "6. Data Klien Sementara (Transient RAM Only)",
            "• user_passphrase\n• derived_kek (CryptoKey)\n• master_key (CryptoKey)\n• file_dek (CryptoKey)\n• plaintext_chunk_buffer\n• decrypted_filename & tags",
            "String\nCryptoKey (non-ext)\nCryptoKey (non-ext)\nCryptoKey (non-ext)\nArrayBuffer\nString",
            "RAM Browser Pengguna (Web Worker)",
            "Kunci diimpor sebagai non-extractable. Hanya bermukim di RAM selama sesi aktif; langsung dihapus saat logout / idle 15 menit."
        ]
    ]
    table(data_widths, data_aligns, data_headers, data_rows)

    callout(
        f"Relevansi Kebutuhan Data di Lingkungan {ORG}:\n"
        "Dengan arsitektur data Zero-Knowledge di atas, berkas-berkas sensitif pengujian sertifikasi keamanan siber "
        "(seperti: dokumen Security Target produk TI, dokumen arsitektur kriptografi perangkat sandi, laporan pengujian "
        "penetrasi kerentanan, serta kode sumber dan citra firmware Target of Evaluation) tersimpan dalam kondisi terenkripsi penuh. "
        "Bahkan jika administrator infrastruktur server atau penyerang internal berhasil mengakses media penyimpanan NAS atau database, "
        "mereka hanya akan menemukan ciphertext acak yang secara matematis tidak dapat didekripsi tanpa passphrase pemilik berkas.",
        "JAMINAN KERAHASIAAN DOKUMEN SERTIFIKASI"
    )

    # ---------------- D. ANALISIS BATASAN SISTEM ----------------
    h1("D. ANALISIS BATASAN SISTEM")
    body(
        "Berdasarkan dokumen PRD Baru, batasan sistem Secure Vault dirumuskan "
        "secara ringkas dan langsung pada poin-poin berikut:"
    )

    bullet("Secure Vault dirancang murni sebagai brankas pribadi terisolasi; tidak mendukung tautan publik (shareable link), kolaborasi berkas, maupun hak akses antar-pengguna.", "1. Tidak Ada Fitur Berbagi Berkas (No File Sharing): ")
    bullet("Sistem hanya dapat diakses melalui web browser desktop/laptop; tidak tersedia aplikasi native untuk Android atau iOS.", "2. Tidak Ada Aplikasi Mobile: ")
    bullet("Tidak tersedia background sync client (seperti Google Drive/OneDrive Sync); seluruh proses unggah dan unduh dilakukan manual via web.", "3. Tidak Ada Sinkronisasi Desktop Otomatis: ")
    bullet("Sistem tidak menyediakan mekanisme pemulihan kunci atau backdoor. Kehilangan passphrase berakibat data musnah permanen dan tidak dapat dipulihkan oleh siapa pun (irrecoverable by design).", "4. Tidak Ada Pemulihan Kunci (No Key Escrow): ")
    bullet("Ukuran maksimal per berkas yang dapat diunggah dibatasi hingga 500 MB pada rilis MVP, diproses per chunk 5 MB.", "5. Batas Ukuran Berkas Maksimal 500 MB: ")
    bullet("Berkas dikelompokkan menggunakan label/tag virtual terenkripsi dalam satu daftar datar (flat-list), tanpa hierarki folder bertingkat.", "6. Struktur Berkas Flat-List: ")
    bullet("Karena isi dan nama berkas terenkripsi secara Zero-Knowledge, server tidak dapat melakukan pengindeksan teks dokumen atau pencarian isi berkas di sisi server.", "7. Tidak Ada Pencarian Isi Dokumen di Server: ")
    bullet("Token akses JWT dibatasi maksimal 15 menit, dan seluruh kunci kriptografi di RAM browser otomatis dihapus (set to null) saat logout atau idle timeout 15 menit.", "8. Masa Berlaku Sesi Pendek (15 Menit): ")
    bullet("Kecepatan derivasi kunci Argon2id (alokasi memori 64 MiB) dan enkripsi/dekripsi AES-256-GCM sangat bergantung pada kapasitas CPU dan RAM komputer pengguna.", "9. Ketergantungan Komputasi Sisi Klien: ")
    bullet("Klien wajib menggunakan peramban modern yang mendukung W3C Web Crypto API, WebAssembly, dan Web Workers; browser lawas tidak didukung.", "10. Persyaratan Peramban Modern: ")
    bullet(f"Seluruh stack sistem wajib di-host on-premise pada server milik {ORG} (simulasi Docker Compose di atas VM Ubuntu Server) tanpa ketergantungan cloud pihak ketiga.", "11. Lingkungan On-Premise Tertutup: ")
    bullet("Basis data PostgreSQL, storage berkas, dan konsol administrasi tidak diekspos ke publik; akses admin dibatasi hanya melalui subnet manajemen internal.", "12. Segmentasi Jaringan & Akses Admin Terisolasi: ")
    bullet("Reverse proxy Nginx membatasi laju permintaan (rate limiting) per pengguna/IP untuk memitigasi serangan brute-force dan DoS.", "13. Batasan Laju Akses (Rate Limiting): ")
    bullet("Fitur resume upload (FR-07), integrasi ELK Stack (FR-15), Wazuh SIEM/FIM, dan token fisik WebAuthn (YubiKey) dialokasikan sebagai backlog pasca-MVP (minggu ke-4 / setelah 35 hari).", "14. Fitur Ditangguhkan ke Backlog (P1/P2): ")
    bullet(f"Ruang lingkup Target of Evaluation (TOE) dibatasi pada aplikasi web klien (React TS) dan server API (Node.js TS) sesuai batasan standar ISO/IEC 15408:2022 (Common Criteria) yang berlaku di {ORG}.", "15. Batasan Konformansi Evaluasi TOE: ")

    # Saving logic with fallbacks
    target_files = [filename, "Analisis_Kebutuhan_Sistem_Secure_Vault_Terbaru.docx", "Analisis_Kebutuhan_Sistem_Secure_Vault_Final.docx"]
    saved_files = []
    for tf in target_files:
        try:
            doc.save(tf)
            saved_files.append(tf)
        except PermissionError:
            pass

    if saved_files:
        print(f"Dokumen berhasil disimpan pada: {', '.join(saved_files)}")
    else:
        alt = "Analisis_Kebutuhan_Sistem_Secure_Vault_v3.docx"
        doc.save(alt)
        print(f"Dokumen disimpan pada: {alt}")


if __name__ == "__main__":
    build()
