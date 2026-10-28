# -*- coding: utf-8 -*-
"""
Script to generate a comprehensive evaluation criteria document in DOCX format:
- ISO/IEC 15408-1:2022 (Common Criteria Part 1)
- ISO/IEC 18045:2026 (Common Evaluation Methodology)
Output: Kriteria_Evaluasi_ISO_15408-1_dan_ISO_18045.docx
"""

import os
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml, OxmlElement
from docx.oxml.ns import nsdecls, qn

def create_evaluation_document(filename="Kriteria_Evaluasi_ISO_15408-1_dan_ISO_18045.docx"):
    doc = docx.Document()

    # 1. Page Setup (Margins: 1 inch = 72 pt)
    sections = doc.sections
    for s in sections:
        s.top_margin = Inches(1.0)
        s.bottom_margin = Inches(1.0)
        s.left_margin = Inches(0.9)
        s.right_margin = Inches(0.9)
        
        # Header & Footer setup
        header = s.header
        hp = header.paragraphs[0]
        hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        hrun = hp.add_run("Kriteria Evaluasi Keamanan IT — ISO/IEC 15408-1:2022 & ISO/IEC 18045:2026")
        hrun.font.name = "Arial"
        hrun.font.size = Pt(8.5)
        hrun.font.color.rgb = RGBColor(120, 120, 120)

        footer = s.footer
        fp = footer.paragraphs[0]
        fp.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        frun = fp.add_run("Dokumen Analisis Kriteria Evaluasi PKL — Proyek Secure Vault | Common Criteria & CEM")
        frun.font.name = "Arial"
        frun.font.size = Pt(8.5)
        frun.font.color.rgb = RGBColor(120, 120, 120)

    # Styling constants
    C_NAVY = RGBColor(27, 54, 93)      # #1B365D
    C_STEEL = RGBColor(43, 84, 126)    # #2B547E
    C_DARK = RGBColor(40, 40, 40)      # #282828
    C_MUTED = RGBColor(100, 100, 100)  # #646464
    HEX_NAVY = "1B365D"
    HEX_LIGHT_BG = "F4F7FA"
    HEX_CALLOUT_BG = "F0F4F8"
    HEX_BORDER = "C6D2DE"

    # Helper: Set paragraph style
    def add_title(text):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(12)
        p.paragraph_format.space_after = Pt(4)
        run = p.add_run(text)
        run.bold = True
        run.font.name = "Arial"
        run.font.size = Pt(20)
        run.font.color.rgb = C_NAVY
        return p

    def add_subtitle(text):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(18)
        run = p.add_run(text)
        run.font.name = "Arial"
        run.font.size = Pt(11.5)
        run.font.color.rgb = C_STEEL
        return p

    def add_h1(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(18)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.bold = True
        run.font.name = "Arial"
        run.font.size = Pt(14)
        run.font.color.rgb = C_NAVY
        return p

    def add_h2(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(13)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.bold = True
        run.font.name = "Arial"
        run.font.size = Pt(11.5)
        run.font.color.rgb = C_STEEL
        return p

    def add_h3(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(9)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.bold = True
        run.font.name = "Arial"
        run.font.size = Pt(10.5)
        run.font.color.rgb = RGBColor(60, 60, 60)
        return p

    def add_body(text, bold_prefix="", italic=False):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.line_spacing = 1.15
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        if bold_prefix:
            br = p.add_run(bold_prefix)
            br.bold = True
            br.font.name = "Arial"
            br.font.size = Pt(9.5)
            br.font.color.rgb = C_DARK
        run = p.add_run(text)
        run.font.name = "Arial"
        run.font.size = Pt(9.5)
        run.italic = italic
        run.font.color.rgb = C_DARK
        return p

    def add_callout(text, title="CATATAN TEKNIS"):
        table = doc.add_table(rows=1, cols=1)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell = table.rows[0].cells[0]
        cell.width = Inches(6.7)
        tcPr = cell._tc.get_or_add_tcPr()
        tcPr.append(parse_xml(f'<w:shd {nsdecls("w")} w:fill="{HEX_CALLOUT_BG}"/>'))
        tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="120" w:type="dxa"/><w:bottom w:w="120" w:type="dxa"/><w:left w:w="180" w:type="dxa"/><w:right w:w="180" w:type="dxa"/></w:tcMar>')
        tcPr.append(tcMar)
        # Left border only (thick navy)
        borders = parse_xml(
            f'<w:tcBorders {nsdecls("w")}>'
            f'<w:top w:val="none"/>'
            f'<w:left w:val="single" w:sz="24" w:space="0" w:color="{HEX_NAVY}"/>'
            f'<w:bottom w:val="none"/>'
            f'<w:right w:val="none"/>'
            f'</w:tcBorders>'
        )
        tcPr.append(borders)
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(2)
        r_title = p.add_run(f"■ {title}\n")
        r_title.bold = True
        r_title.font.name = "Arial"
        r_title.font.size = Pt(9.5)
        r_title.font.color.rgb = C_NAVY
        r_text = p.add_run(text)
        r_text.font.name = "Arial"
        r_text.font.size = Pt(9)
        r_text.font.color.rgb = C_DARK
        doc.add_paragraph().paragraph_format.space_after = Pt(3)

    def create_table(col_widths, col_alignments, col_headers, data_rows):
        tbl = doc.add_table(rows=len(data_rows) + 1, cols=len(col_headers))
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        
        # Table borders
        tblPr = tbl._tbl.tblPr
        borders = parse_xml(
            f'<w:tblBorders {nsdecls("w")}>'
            f'<w:top w:val="single" w:sz="6" w:space="0" w:color="{HEX_NAVY}"/>'
            f'<w:bottom w:val="single" w:sz="6" w:space="0" w:color="{HEX_NAVY}"/>'
            f'<w:left w:val="single" w:sz="4" w:space="0" w:color="{HEX_BORDER}"/>'
            f'<w:right w:val="single" w:sz="4" w:space="0" w:color="{HEX_BORDER}"/>'
            f'<w:insideH w:val="single" w:sz="4" w:space="0" w:color="{HEX_BORDER}"/>'
            f'<w:insideV w:val="single" w:sz="4" w:space="0" w:color="{HEX_BORDER}"/>'
            f'</w:tblBorders>'
        )
        tblPr.append(borders)

        # Header Row
        hdr_row = tbl.rows[0]
        trPr = hdr_row._tr.get_or_add_trPr()
        trPr.append(parse_xml(f'<w:tblHeader {nsdecls("w")}/>'))
        trPr.append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))

        for i, header_text in enumerate(col_headers):
            cell = hdr_row.cells[i]
            cell.width = Inches(col_widths[i])
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            tcPr = cell._tc.get_or_add_tcPr()
            tcPr.append(parse_xml(f'<w:shd {nsdecls("w")} w:fill="{HEX_NAVY}"/>'))
            tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="120" w:type="dxa"/><w:bottom w:w="120" w:type="dxa"/><w:left w:w="140" w:type="dxa"/><w:right w:w="140" w:type="dxa"/></w:tcMar>')
            tcPr.append(tcMar)
            
            p = cell.paragraphs[0]
            p.alignment = col_alignments[i]
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.line_spacing = 1.1
            run = p.add_run(header_text)
            run.bold = True
            run.font.name = "Arial"
            run.font.size = Pt(9)
            run.font.color.rgb = RGBColor(255, 255, 255)

        # Data Rows
        for r_idx, row_data in enumerate(data_rows):
            row = tbl.rows[r_idx + 1]
            r_trPr = row._tr.get_or_add_trPr()
            r_trPr.append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))
            bg_color = HEX_LIGHT_BG if r_idx % 2 == 1 else "FFFFFF"

            for c_idx, val in enumerate(row_data):
                cell = row.cells[c_idx]
                cell.width = Inches(col_widths[c_idx])
                cell.vertical_alignment = WD_ALIGN_VERTICAL.TOP
                tcPr = cell._tc.get_or_add_tcPr()
                if bg_color != "FFFFFF":
                    tcPr.append(parse_xml(f'<w:shd {nsdecls("w")} w:fill="{bg_color}"/>'))
                tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="90" w:type="dxa"/><w:bottom w:w="90" w:type="dxa"/><w:left w:w="130" w:type="dxa"/><w:right w:w="130" w:type="dxa"/></w:tcMar>')
                tcPr.append(tcMar)

                p = cell.paragraphs[0]
                p.alignment = col_alignments[c_idx]
                p.paragraph_format.space_before = Pt(0)
                p.paragraph_format.space_after = Pt(0)
                p.paragraph_format.line_spacing = 1.15
                
                # Check for formatting (bold title if contains ':')
                text_str = str(val)
                run = p.add_run(text_str)
                run.font.name = "Arial"
                run.font.size = Pt(8.5)
                run.font.color.rgb = C_DARK

        doc.add_paragraph().paragraph_format.space_after = Pt(6)
        return tbl

    print("Helper functions initialized. Generating content...")

    # -------------------------------------------------------------
    # COVER / HEADER BLOCK
    # -------------------------------------------------------------
    add_title("TABEL KRITERIA EVALUASI KEAMANAN SISTEM INFORMASI")
    add_subtitle("Kompilasi dan Komparasi Kriteria Berdasarkan ISO/IEC 15408-1:2022 (Common Criteria) dan ISO/IEC 18045:2026 (Common Evaluation Methodology)")

    add_callout(
        "Dokumen ini menyajikan tabulasi komprehensif kriteria evaluasi keamanan teknologi informasi yang diturunkan secara langsung dari dua pilar standar keamanan internasional:\n"
        "1. ISO/IEC 15408-1:2022 (Common Criteria for IT Security Evaluation — Part 1: Introduction and general model, Fourth Edition 2022-08)\n"
        "2. ISO/IEC 18045:2026 (Common Evaluation Methodology for IT Security Evaluation — Requirements and methodology, Edition 2026)\n"
        "Kedua standar disajikan dalam tabel evaluasi masing-masing secara mendalam, terstruktur, dan analitis, dilengkapi dengan sintesis korelasi dan panduan aplikatif untuk evaluasi sistem Secure Vault.",
        "RINGKASAN EKSEKUTIF & INFORMASI DOKUMEN"
    )

    # Metadata Table
    meta_headers = ["Atribut Dokumen", "Rincian Teknis"]
    meta_widths = [2.2, 4.5]
    meta_aligns = [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT]
    meta_data = [
        ["Judul Laporan", "Tabel Kriteria Evaluasi Keamanan Sistem Informasi (ISO/IEC 15408-1 & ISO/IEC 18045)"],
        ["Konteks Analisis", "Program Praktik Kerja Lapangan (PKL) — Rekayasa Keamanan & Evaluasi Secure Vault"],
        ["Standar Acuan Utama 1", "ISO/IEC 15408-1:2022(E) — Fourth Edition 2022-08 (Information security, cybersecurity and privacy protection — Evaluation criteria for IT security — Part 1: Introduction and general model)"],
        ["Standar Acuan Utama 2", "ISO/IEC 18045:2026(en) — Edition 2026 (Information security, cybersecurity and privacy protection — Evaluation criteria for IT security — Requirements and methodology for IT security evaluation)"],
        ["Format & Target Luaran", "Satu dokumen tunggal Microsoft Word (.docx) dengan tabel terpisah per standar"],
        ["Klasifikasi & Status", "Laporan Teknis / Evaluasi Komprehensif Baseline Keamanan"],
    ]
    create_table(meta_widths, meta_aligns, meta_headers, meta_data)

    # -------------------------------------------------------------
    # PENDAHULUAN
    # -------------------------------------------------------------
    add_h1("1. PENDAHULUAN DAN KERANGKA UMUM EVALUASI")
    add_body(
        "Evaluasi keamanan produk dan sistem Teknologi Informasi (TI) secara internasional mengacu pada kerangka kerja Common Criteria (CC) yang distandardisasi melalui ISO/IEC 15408 dan metodologi operasionalnya yang diatur dalam ISO/IEC 18045 (Common Evaluation Methodology - CEM). Kedua standar ini memiliki relasi simbiotik: ISO/IEC 15408 mendefinisikan 'APA' kriteria yang harus dipenuhi oleh produk (Target of Evaluation - TOE), dokumen Protection Profile (PP), dan Security Target (ST), sedangkan ISO/IEC 18045 mendefinisikan 'BAGAIMANA' evaluator melakukan verifikasi, pengujian, dan penentuan putusan (verdict)."
    )
    add_body(
        "Pada versi terbarunya (ISO/IEC 15408-1:2022 dan ISO/IEC 18045:2026), terdapat sejumlah pembaruan fundamental, antara lain pengenalan konstruksi modular (PP-Module dan PP-Configuration), formalisasi tiga tipe konformansi (Strict, Demonstrable, dan Exact Conformance), format Direct Rationale Security Target, serta penyempurnaan metodologi evaluasi komposit dan penilaian kerentanan berbasis attack potential."
    )

    # -------------------------------------------------------------
    # BAGIAN I: ISO/IEC 15408-1:2022
    # -------------------------------------------------------------
    add_h1("2. BAGIAN I: TABEL KRITERIA EVALUASI BERDASARKAN ISO/IEC 15408-1:2022")
    add_body(
        "ISO/IEC 15408-1:2022 menetapkan konsep, model umum, dan paradigma evaluasi keamanan TI. Standar ini mendefinisikan struktur taksonomi keamanan, prinsip penyusunan batasan TOE, pendefinisian masalah keamanan, penetapan sasaran, konstruksi kebutuhan modular, serta spesifikasi normatif untuk paket jaminan (assurance packages), Protection Profile (PP), dan Security Target (ST)."
    )

    # Tabel 1.1: Paradigma Dasar & SPD
    add_h2("2.1 Kriteria Paradigma Dasar & Definisi Masalah Keamanan (Security Problem Definition - SPD)")
    add_body(
        "Kriteria pada tabel ini mengevaluasi kelengkapan dan konsistensi pendefinisian konteks keamanan TOE sebagaimana diatur pada Klausul 6 dan 7 ISO/IEC 15408-1:2022."
    )
    
    t1_1_headers = ["ID Kriteria", "Dimensi Evaluasi", "Kriteria Evaluasi ISO/IEC 15408-1:2022", "Indikator Verifikasi", "Tingkat Kekritisan"]
    t1_1_widths = [0.9, 1.4, 2.3, 1.5, 0.6]
    t1_1_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t1_1_data = [
        ["CRIT-15408-01", "Identifikasi Aset (Assets)", "Aset primer (data/fungsi) dan aset sekunder (komponen TSF) harus didefinisikan secara eksplisit beserta nilai sensitivitasnya (kerahasiaan, integritas, ketersediaan).", "Inventaris aset lengkap, klasifikasi proteksi jelas, tidak ada aset tersembunyi.", "Kritis"],
        ["CRIT-15408-02", "Agen Ancaman (Threat Agents)", "Profil penyerang harus diidentifikasi meliputi aspek keahlian (expertise), sumber daya finansial/komputasi, motivasi serangan, dan aksesibilitas.", "Deskripsi pelaku ancaman realistis terhadap konteks operasional TOE.", "Tinggi"],
        ["CRIT-15408-03", "Skenario Ancaman (Threats)", "Ancaman harus dirumuskan sebagai kombinasi agen ancaman, jalur serangan (attack vector), dan dampak terhadap aset tertentu.", "Format ancaman T.[NAMA] terdefinisi konsisten dan tidak ambigu.", "Kritis"],
        ["CRIT-15408-04", "Kebijakan Keamanan (OSP)", "Kebijakan Keamanan Organisasi (Organizational Security Policies) harus memuat aturan formal, hukum, regulasi, atau standar eksternal yang wajib ditegakkan.", "Format OSP.[NAMA], dapat diverifikasi keterkaitannya dengan fungsi TOE.", "Sedang"],
        ["CRIT-15408-05", "Asumsi Lingkungan (Assumptions)", "Kondisi fisik, personel, dan jaringan lingkungan operasional di luar kendali TOE harus dinyatakan tanpa menimbulkan celah mitigasi fungsional.", "Format A.[NAMA], rasional, tidak membebankan tanggung jawab inti TOE ke lingkungan.", "Tinggi"],
        ["CRIT-15408-06", "Batasan TOE (TOE Boundary)", "Batasan fisik (hardware, port, enclosure) dan batasan logis (antarmuka API, protokol, boundary proses) harus digambarkan secara tegas dan konsisten.", "Pemisahan jelas antara bagian yang dievaluasi dan lingkungan non-TOE.", "Kritis"]
    ]
    create_table(t1_1_widths, t1_1_aligns, t1_1_headers, t1_1_data)

    # Tabel 1.2: Sasaran Keamanan
    add_h2("2.2 Kriteria Perumusan Sasaran Keamanan (Security Objectives Criteria)")
    add_body(
        "Sasaran keamanan mentransformasikan masalah keamanan (SPD) menjadi pernyataan tujuan terarah bagi TOE dan lingkungan operasionalnya (Klausul 7.2 ISO/IEC 15408-1:2022)."
    )

    t1_2_headers = ["ID Kriteria", "Kategori Sasaran", "Kriteria Evaluasi ISO/IEC 15408-1:2022", "Parameter Keterlacakan (Traceability)", "Hasil yang Diharapkan"]
    t1_2_widths = [1.0, 1.4, 2.3, 1.3, 0.7]
    t1_2_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t1_2_data = [
        ["CRIT-15408-07", "Sasaran untuk TOE (OT.*)", "Sasaran teknis yang harus dicapai langsung oleh fungsi keamanan TOE (TSF) untuk memitigasi ancaman dan menegakkan OSP terkait.", "Setiap OT.* harus memetakan ke minimal satu ancaman (T.*) atau OSP.*.", "Lengkap & Tepat"],
        ["CRIT-15408-08", "Sasaran Lingkungan (OE.*)", "Sasaran yang dialokasikan kepada lingkungan operasional (kebijakan fisik, admin terpercaya, jaringan aman) untuk memenuhi asumsi (A.*).", "Setiap OE.* harus memetakan ke minimal satu asumsi (A.*) atau OSP.* lingkungan.", "Terpetakan"],
        ["CRIT-15408-09", "Matriks Keterlacakan (Traceability)", "Harus disediakan tabel pemetaan dwiarah (bidirectional mapping) yang menghubungkan seluruh aspek SPD ke Sasaran Keamanan tanpa ada yang terlewat.", "Tidak boleh ada elemen SPD yang tidak terjawab (orphan SPD items).", "Konsisten 100%"],
        ["CRIT-15408-10", "Rasionalisasi Kecukupan (Sufficiency Rationale)", "Justifikasi logis terinci yang membuktikan bahwa pemenuhan seluruh sasaran keamanan menjamin ancaman termitigasi secara tuntas dan OSP terpenuhi.", "Argumen logis yang menunjukkan tidak ada skenario serangan yang lolos.", "Valid & Cukup"]
    ]
    create_table(t1_2_widths, t1_2_aligns, t1_2_headers, t1_2_data)

    # Tabel 1.3: Hirarki Komponen & Operasi
    add_h2("2.3 Kriteria Taksonomi dan Operasi Kebutuhan Keamanan (Class, Family, Component, Element)")
    add_body(
        "Kriteria ini mengatur taksonomi hierarkis komponen keamanan dan 4 operasi resmi yang diizinkan untuk menyesuaikan komponen standar (Klausul 8 ISO/IEC 15408-1:2022)."
    )

    t1_3_headers = ["Konstruk / Operasi", "Tingkatan", "Aturan & Kriteria Evaluasi ISO/IEC 15408-1:2022", "Format Penulisan / Notasi Resmi", "Batasan Kepatuhan"]
    t1_3_widths = [1.2, 0.9, 2.3, 1.4, 0.9]
    t1_3_aligns = [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT]
    t1_3_data = [
        ["Kelas (Class)", "Level 1", "Pengelompokan kebutuhan keamanan dengan tema/fokus umum yang sama (misal ADV untuk pengembangan, FCS untuk kriptografi).", "3 karakter huruf besar (misal FCS, ADV, ATE).", "Wajib sesuai katalog CC"],
        ["Keluarga (Family)", "Level 2", "Himpunan kebutuhan yang berbagi sasaran keamanan serupa tetapi bervariasi dalam ketelitian, kedalaman, atau penekanan.", "4 karakter (3 huruf kelas + 1 huruf keluarga, misal FCS_COP, ADV_FSP).", "Wajib sesuai katalog CC"],
        ["Komponen (Component)", "Level 3", "Unit terkecil yang dapat dipilih dalam menyusun profil jaminan atau fungsional dalam ST/PP.", "Kode keluarga + digit numerik (misal FCS_COP.1, ADV_FSP.4).", "Atomic selection"],
        ["Elemen (Element)", "Level 4", "Pernyataan kebutuhan atomik yang tidak dapat dibagi lagi. Terdiri atas Developer Action, Content/Presentation, dan Evaluator Action.", "Kode komponen + digit elemen (misal ADV_FSP.4.1D, ADV_FSP.4.1C, ADV_FSP.4.1E).", "Dasar verifikasi pengujian"],
        ["Assignment (Penetapan)", "Operasi", "Pengisian nilai parameter tertentu yang disediakan oleh komponen standar (misal daftar algoritma, panjang kunci, waktu timeout).", "[assignment: daftar algoritma yang didukung]", "Tidak boleh dibiarkan kosong"],
        ["Selection (Pemilihan)", "Operasi", "Pemilihan satu atau beberapa alternatif opsi yang disediakan secara eksplisit dalam komponen standar.", "[selection: read, write, delete]", "Hanya memilih dari opsi standar"],
        ["Refinement (Perincian)", "Operasi", "Penambahan rincian teknis presisi pada kebutuhan standar tanpa mengubah atau mempersempit makna/lingkup dasarnya.", "Teks cetak tebal (bold) atau garis bawah (underline).", "Tidak boleh melonggarkan"],
        ["Iteration (Iterasi)", "Operasi", "Penggunaan berulang komponen yang sama dengan operasi assignment/selection berbeda untuk fungsi/entitas yang berbeda.", "Kode komponen/pengidentifikasi unik (misal FCS_COP.1/AES, FCS_COP.1/RSA).", "Harus diberi label pembeda"],
        ["Extended Components", "Perluasan", "Penyusunan komponen baru jika katalog standar ISO/IEC 15408-2 atau 15408-3 tidak memiliki kebutuhan yang sesuai.", "Diawali '_EXT' (misal FCS_RNG_EXT.1), wajib ada definisi lengkap elemen D/C/E.", "Wajib didefinisikan di Bab ECD"]
    ]
    create_table(t1_3_widths, t1_3_aligns, t1_3_headers, t1_3_data)

    # Tabel 1.4: Paket Jaminan & EAL
    add_h2("2.4 Kriteria Paket Keamanan (Assurance Packages, EAL1 - EAL7, dan Functional Packages)")
    add_body(
        "Kriteria ini mengevaluasi Evaluation Assurance Levels (EAL) dan paket fungsional sebagaimana didefinisikan pada Klausul 9 dan Annex A ISO/IEC 15408-1:2022."
    )

    t1_4_headers = ["Paket / Level", "Nama Resmi", "Karakteristik & Kedalaman Kriteria Evaluasi", "Metodologi Verifikasi Utama", "Kelayakan Penerapan"]
    t1_4_widths = [1.1, 1.4, 2.3, 1.1, 0.8]
    t1_4_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t1_4_data = [
        ["EAL1", "Functionally Tested", "Memberikan bukti bahwa produk beroperasi sesuai dokumentasi. Evaluasi tanpa memerlukan akses ke kode sumber pengembang.", "Uji fungsional independen terhadap spesifikasi antarmuka eksternal.", "Produk komersial massal dasar"],
        ["EAL2", "Structurally Tested", "Memerlukan pengujian pengembang, analisis kerentanan dasar, dan peninjauan arsitektur sistem tingkat tinggi.", "Pemeriksaan spesifikasi desain dasar dan audit konfigurasi.", "Sistem TI warisan (legacy)"],
        ["EAL3", "Methodically Tested & Checked", "Memerlukan kontrol lingkungan pengembangan pengembang (ALC_DVS.1) dan pengujian fungsional modul terstruktur.", "Verifikasi metodis mekanisme proteksi dan prosedur rilis.", "Sistem enterprise moderat"],
        ["EAL4", "Methodically Designed, Tested & Reviewed", "Level tertinggi yang layak secara ekonomi tanpa teknik rekayasa khusus. Memerlukan peninjauan representasi implementasi parsial dan analisis kerentanan terstruktur.", "Analisis kode parsial, pengujian penetrasi independen, kontrol siklus hidup penuh.", "Standar industri komersial tinggi"],
        ["EAL5", "Semiformally Designed & Tested", "Memerlukan desain modular semi-formal, arsitektur keamanan ketat (non-bypassability, domain separation), dan keterlacakan menyeluruh.", "Analisis arsitektural mendalam, peninjauan kode sumber menyeluruh, uji penetrasi terarah.", "Hardware security, Smart Card"],
        ["EAL6", "Semiformally Verified Design & Tested", "Memerlukan analisis semi-formal berlapis, pembuktian keamanan struktural, dan mitigasi serangan terencana canggih.", "Verifikasi semi-formal desain dan representasi implementasi.", "Sistem militer / infrastruktur kritis"],
        ["EAL7", "Formally Verified Design & Tested", "Tingkat jaminan tertinggi. Memerlukan pembuktian formal matematis terhadap korespondensi desain dan pengujian komprehensif independen.", "Pembuktian teorema matematika formal terhadap model kebijakan keamanan.", "Aplikasi pertahanan ultra-kritis"],
        ["CAP", "Composed Assurance Package", "Paket jaminan khusus untuk evaluasi TOE komposit yang terdiri dari modul-modul yang telah dievaluasi sebelumnya.", "Evaluasi ketergantungan (ACO_REL), pengujian komposit (ACO_CTT).", "Sistem terintegrasi modular"],
        ["Functional Package", "Paket Fungsional (FP)", "Kumpulan komponen SFR yang distandarisasi untuk domain fungsional spesifik (misal: modul kriptografi, client TLS).", "Verifikasi pemenuhan seluruh SFR dalam paket tanpa modifikasi melemahkan.", "Modul pluggable terdefinisi"]
    ]
    create_table(t1_4_widths, t1_4_aligns, t1_4_headers, t1_4_data)

    # Tabel 1.5: Protection Profile (PP) & Conformance Types
    add_h2("2.5 Kriteria Evaluasi Protection Profile (PP) dan Tipe Konformansi (Conformance Types)")
    add_body(
        "Klausul 10 dan Annex B & E ISO/IEC 15408-1:2022 mendefinisikan persyaratan evaluasi dokumen Protection Profile serta tiga tipe klaim kesesuaian (Strict, Demonstrable, dan Exact Conformance)."
    )

    t1_5_headers = ["Elemen PP / Tipe", "Kategori Kriteria", "Deskripsi Kriteria Evaluasi ISO/IEC 15408-1:2022", "Syarat Kelulusan Evaluasi", "Relevansi Evaluasi"]
    t1_5_widths = [1.2, 1.2, 2.3, 1.3, 0.7]
    t1_5_aligns = [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t1_5_data = [
        ["PP Introduction", "Struktur Inti PP", "Harus memuat identifikasi PP unik, ringkasan fungsional TOE, deskripsi arsitektur konseptual, dan batasan evaluasi.", "Identifikasi PP jelas, nomor registrasi valid, deskripsi representatif.", "Wajib"],
        ["Conformance Claims", "Struktur Inti PP", "Pernyataan versi CC yang diacu, klaim paket jaminan (EAL), dan spesifikasi tipe konformansi yang diwajibkan bagi ST.", "Klaim versi CC (misal v3.1R5 atau 2022), paket EAL valid.", "Wajib"],
        ["Strict Conformance", "Tipe Konformansi", "ST atau PP turunan harus memenuhi semua kebutuhan PP dasar. Kebutuhan pada ST harus merupakan subset hierarkis atau setara persis; tidak boleh ada pelonggaran.", "SPD dan Sasaran ST tidak boleh bertentangan; SFR ST setara atau lebih ketat.", "Ketat & Presisi"],
        ["Demonstrable Conformance", "Tipe Konformansi", "ST dapat merumuskan solusi keamanan yang ekivalen secara logis dengan PP, meskipun formulasi ancaman atau sasaran berbeda, dengan menyertakan rasionalisasi.", "Rasionalisasi ekivalensi logis terbukti valid dan komprehensif.", "Fleksibel"],
        ["Exact Conformance", "Tipe Konformansi (Fitur Baru 2022)", "Kebutuhan pada ST harus persis 100% identik dengan PP tanpa penambahan atau pengurangan SFR/SAR mandiri (kecuali operasi yang diizinkan PP).", "Identik secara tekstual dan struktural, tidak ada deviasi kebutuhan.", "cPP Modern"],
        ["Extended Components Def.", "Struktur Inti PP", "Mendefinisikan setiap kelas, keluarga, dan komponen baru yang tidak tercantum dalam ISO/IEC 15408-2 atau 15408-3.", "Format taksonomi lengkap (elemen D, C, E), deskripsi audit dan dependensi jelas.", "Kondisional"],
        ["Security Requirements", "Struktur Inti PP", "Menyatakan SFR dan SAR yang dipilih, menyelesaikan semua operasi yang ditentukan, dan memverifikasi dependensi antar komponen.", "Semua operasi valid, dependensi terselesaikan secara lengkap.", "Wajib"]
    ]
    create_table(t1_5_widths, t1_5_aligns, t1_5_headers, t1_5_data)

    # Tabel 1.6: Modular Requirements Construction (PP-Module & PP-Configuration)
    add_h2("2.6 Kriteria Konstruksi Kebutuhan Modular (PP-Module dan PP-Configuration)")
    add_body(
        "Klausul 11 dan Annex C ISO/IEC 15408-1:2022 memperkenalkan arsitektur modular yang memungkinkan pembentukan konfigurasi profil perlindungan gabungan secara dinamis."
    )

    t1_6_headers = ["Entitas Modular", "Dimensi Kriteria", "Persyaratan Teknis ISO/IEC 15408-1:2022", "Metode Evaluasi Konsistensi", "Hasil Evaluasi"]
    t1_6_widths = [1.2, 1.2, 2.3, 1.3, 0.7]
    t1_6_aligns = [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t1_6_data = [
        ["PP-Module", "Base PP Requirement", "PP-Module harus mendefinisikan secara eksplisit satu atau lebih Base PP yang menjadi landasannya, atau Base PP-Module lain.", "Verifikasi kecocokan antarmuka dan batasan fungsional dengan Base PP.", "Kompatibel"],
        ["PP-Module", "Perluasan SPD & Sasaran", "Mendefinisikan ancaman, OSP, dan asumsi tambahan yang relevan dengan fitur spesifik modul tanpa mengubah batasan Base PP.", "Pemeriksaan tidak adanya tumpang tindih kontradiktif antara SPD modul dan base.", "Bebas Konflik"],
        ["PP-Module", "Konsistensi Modul (ACE_MCO)", "Menganalisis tidak adanya konflik antara SFR/SAR yang didefinisikan modul dengan Base PP yang mendasarinya.", "Analisis ketergantungan silang (cross-dependency analysis).", "Harmonis"],
        ["PP-Configuration", "Spesifikasi Konfigurasi", "Mengidentifikasi sekumpulan komponen yang dievaluasi bersama: tepat satu atau lebih Base PP ditambah satu atau lebih PP-Module.", "Daftar komponen konfigurasi terdefinisi jelas dengan nomor versi tepat.", "Unik & Utuh"],
        ["PP-Configuration", "Konsistensi Konfigurasi (ACE_CCO)", "Memastikan bahwa kombinasi Base PP dan modul-modul terkait membentuk sistem proteksi keamanan yang utuh, tanpa celah antarmuka.", "Verifikasi penutupan seluruh batasan antarmuka antar modul.", "Kohesif"],
        ["PP-Configuration", "Penyelesaian Dependensi", "Seluruh dependensi SFR dan SAR di seluruh modul dalam konfigurasi harus terselesaikan di dalam konfigurasi atau dialokasikan ke lingkungan.", "Matriks resolusi dependensi holistik.", "Lengkap 100%"]
    ]
    create_table(t1_6_widths, t1_6_aligns, t1_6_headers, t1_6_data)

    # Tabel 1.7: Security Target (ST) & Direct Rationale ST
    add_h2("2.7 Kriteria Evaluasi Dokumen Security Target (ST) dan Spesifikasi Ringkasan TOE (TSS)")
    add_body(
        "Klausul 12 dan Annex D ISO/IEC 15408-1:2022 mengatur struktur dokumen ST spesifik produk, termasuk format Direct Rationale ST dan evaluasi TOE Summary Specification."
    )

    t1_7_headers = ["Bagian ST", "Model ST", "Kriteria Evaluasi ISO/IEC 15408-1:2022", "Indikator Verifikasi", "Tingkat Verifikasi"]
    t1_7_widths = [1.2, 1.1, 2.3, 1.4, 0.7]
    t1_7_aligns = [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t1_7_data = [
        ["ST Introduction", "Semua Model", "Memuat identifikasi ST dan TOE secara presisi (termasuk versi build hardware/software) dan ringkasan fungsional TOE.", "Nomor versi persis, deskripsi tidak bertentangan dengan produk nyata.", "Kritis"],
        ["Conformance Claims", "Semua Model", "Pernyataan kepatuhan terhadap standar CC, klaim konformansi terhadap PP/PP-Configuration, dan klaim paket EAL.", "Validasi sertifikasi PP yang diacu dan kesesuaian tipe konformansi.", "Kritis"],
        ["Security Objectives", "Full Rationale ST", "Format standar CC: SPD dipetakan ke Sasaran Keamanan, lalu Sasaran Keamanan dipetakan ke Kebutuhan Keamanan (SFR/SAR).", "Traceability ganda: SPD -> Objectives -> Requirements lengkap.", "Standar CC"],
        ["Direct Rationale ST", "Direct Rationale (Fitur Baru 2022)", "Format baru yang mengizinkan pemetaan langsung dari SPD ke SFR tanpa mendefinisikan Sasaran Keamanan perantara.", "Matriks langsung SPD -> SFR, disertai rasionalisasi kecukupan langsung.", "Efisien & Ketat"],
        ["TOE Summary Spec. (TSS)", "Semua Model", "Deskripsi naratif teknis mengenai bagaimana mekanisme keamanan TSF mengimplementasikan setiap SFR yang dinyatakan dalam ST.", "Setiap SFR harus memiliki deskripsi mekanisme implementasi konkret di TSS.", "Kritis"],
        ["Multi-Assurance Case", "Multi-Assurance ST", "Penanganan TOE kompleks di mana komponen-komponen yang berbeda memiliki target level asuransi berbeda dalam 1 ST.", "Pemisahan batas jaminan yang tegas antar subsistem, tidak ada kontaminasi jaminan rendah ke tinggi.", "Tinggi"]
    ]
    create_table(t1_7_widths, t1_7_aligns, t1_7_headers, t1_7_data)

    # Tabel 1.8: Penetapan Hasil Evaluasi & Model Komposisi Jaminan
    add_h2("2.8 Kriteria Penetapan Hasil Evaluasi dan Model Komposisi Jaminan (Composition of Assurance)")
    add_body(
        "Klausul 13 dan 14 ISO/IEC 15408-1:2022 mengatur kriteria penetapan putusan evaluasi serta model evaluasi komposit untuk sistem terintegrasi."
    )

    t1_8_headers = ["Dimensi", "Komponen / Model", "Kriteria Evaluasi ISO/IEC 15408-1:2022", "Konsekuensi Evaluasi", "Status Putusan"]
    t1_8_widths = [1.1, 1.3, 2.3, 1.3, 0.7]
    t1_8_aligns = [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t1_8_data = [
        ["Verdict Evaluasi", "PASS (Lulus)", "Semua bukti evaluasi telah diperiksa, semua unit kerja evaluator bernilai PASS, tidak ada kerentanan terbuka yang dapat dieksploitasi.", "Sertifikat CC dapat diterbitkan oleh badan sertifikasi.", "Lulus"],
        ["Verdict Evaluasi", "FAIL (Gagal)", "Terdapat minimal satu unit kerja evaluator yang bernilai FAIL, atau ditemukan kerentanan yang tidak dapat dimitigasi.", "Evaluasi dihentikan atau dikembalikan ke pengembang untuk perbaikan (Observation Report).", "Gagal"],
        ["Verdict Evaluasi", "INCONCLUSIVE", "Bukti evaluasi tidak memadai atau pengujian tidak dapat diselesaikan karena kendala teknis di luar lingkup.", "Diperlukan bukti tambahan atau penjadwalan ulang pengujian.", "Tertunda"],
        ["Model Komposisi", "Layered Composition", "Model di mana TOE aplikasi berjalan di atas TOE platform dasar yang telah tersertifikasi sebelumnya (misal OS di atas Secure Element).", "Hasil sertifikasi platform dasar dapat digunakan kembali (re-use of results).", "Re-usable"],
        ["Model Komposisi", "Network / Bi-directional", "Model di mana dua atau lebih TOE saling berkomunikasi secara horizontal melalui protokol jaringan aman.", "Evaluasi antarmuka komunikasi dan asumsi timbal-balik.", "Verifikasi Bersama"],
        ["Model Komposisi", "Embedded Composition", "Model di mana modul keamanan tertanam secara fisik atau firmware di dalam sistem induk yang lebih besar.", "Analisis isolasi fisik dan logis antar modul.", "Terintegrasi"],
        ["Komposit vs ACO", "Composite Evaluation", "Metode praktis yang memanfaatkan ETR for Composite Evaluation dari platform dasar untuk mengevaluasi produk komposit akhir.", "Efisiensi waktu dan biaya tinggi; fokus pada kerentanan komposit.", "Pilihan Industri"]
    ]
    create_table(t1_8_widths, t1_8_aligns, t1_8_headers, t1_8_data)

    # -------------------------------------------------------------
    # BAGIAN II: ISO/IEC 18045:2026
    # -------------------------------------------------------------
    add_h1("3. BAGIAN II: TABEL KRITERIA EVALUASI BERDASARKAN ISO/IEC 18045:2026 (CEM)")
    add_body(
        "ISO/IEC 18045:2026 (Common Evaluation Methodology - CEM) mendefinisikan persyaratan operasional, alur tugas evaluasi, tindakan minimum evaluator (minimum evaluator actions), dan unit kerja (work units) untuk setiap kelas jaminan keamanan Common Criteria. Edisi 2026 menyempurnakan panduan peninjauan arsitektur, pengujian fungsional komposit, serta metodologi evaluasi kerentanan berbasis perhitungan attack potential."
    )

    # Tabel 2.1: Alur Kerja CEM & Peran
    add_h2("3.1 Kerangka Kerja, Alur Proses, dan Tata Kelola Evaluasi (Evaluation Process & Roles)")
    add_body(
        "Klausul 8 ISO/IEC 18045:2026 mendefinisikan siklus hidup evaluasi keamanan, peran-peran yang terlibat, serta mekanisme pelaporan temuan."
    )

    t2_1_headers = ["Tahap / Peran", "Entitas Terkait", "Tanggung Jawab & Tindakan Normatif ISO/IEC 18045:2026", "Artefak yang Dihasilkan", "Kriteria Kualitas"]
    t2_1_widths = [1.1, 1.1, 2.4, 1.4, 0.7]
    t2_1_aligns = [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t2_1_data = [
        ["Evaluation Input Task", "Evaluator & Sponsor", "Evaluator memeriksa kelengkapan bukti evaluasi (TOE, ST, dokumen panduan, bukti desain, sampel pengujian) sebelum memulai evaluasi formal.", "Log Penerimaan Bukti (Evidence Receipt & Check).", "Lengkap & Valid"],
        ["Sub-activities Execution", "Evaluator", "Evaluator menjalankan seluruh unit kerja (work units) pada setiap kelas jaminan sesuai EAL target menggunakan kata kerja normatif 'shall'.", "Catatan Kerja Evaluator (Work Unit Records).", "Metodis & Obyektif"],
        ["Observation Report (OR)", "Evaluator & Developer", "Evaluator mendokumentasikan setiap ketidaksesuaian, keraguan, atau kegagalan bukti evaluasi untuk diklarifikasi/diperbaiki oleh pengembang.", "Dokumen Observation Report (OR).", "Jelas & Terdokumentasi"],
        ["Evaluation Output Task", "Evaluator & Certifier", "Evaluator menyusun laporan teknis komprehensif yang merangkum seluruh hasil evaluasi, justifikasi putusan, dan rekomendasi sertifikasi.", "Evaluation Technical Report (ETR).", "Komprehensif"],
        ["Certification / Validation", "Badan Sertifikasi (CB)", "Badan sertifikasi independen meninjau ETR, mengawasi kepatuhan evaluator terhadap ISO 18045, dan menerbitkan sertifikat resmi.", "Sertifikat CC & Certification Report (CR).", "Otoritatif"],
        ["Kata Kerja Normatif", "Semua Work Unit", "Penggunaan auxiliary verb 'shall' bersama kata kerja evaluasi presisi: confirm (periksa independen), check (verifikasi eksistensi), examine (telaah teliti), determine (putuskan kepastian).", "Tingkat ketelitian verifikasi standar di seluruh laboratorium evaluasi.", "Teredukasi & Baku"]
    ]
    create_table(t2_1_widths, t2_1_aligns, t2_1_headers, t2_1_data)

    # Tabel 2.2: Kelas APE
    add_h2("3.2 Kriteria Evaluasi Kelas APE (Protection Profile Evaluation - Klausul 9)")
    add_body(
        "Kelas APE memverifikasi bahwa Protection Profile disusun secara benar, lengkap, konsisten, dan layak digunakan sebagai acuan evaluasi ST."
    )

    t2_2_headers = ["Sub-Aktivitas", "Nama Keluarga / Komponen", "Bukti Evaluasi (Evidence)", "Tindakan Minimum Evaluator (Work Units)", "Kriteria Putusan PASS"]
    t2_2_widths = [1.0, 1.4, 1.6, 2.0, 0.7]
    t2_2_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t2_2_data = [
        ["APE_INT.1", "PP Introduction", "Dokumen draft Protection Profile.", "Evaluator memeriksa identifikasi PP, deskripsi TOE, dan ringkasan fungsional agar konsisten dan tidak menyesatkan.", "Identifikasi unik & deskripsi jelas"],
        ["APE_CCL.1", "Conformance Claims", "Klaim konformansi dalam PP.", "Evaluator mengonfirmasi klaim versi CC, paket EAL, dan tipe konformansi yang disyaratkan bagi ST yang mengacu.", "Klaim standar valid & terdefinisi"],
        ["APE_SPD.1", "Security Problem Definition", "Pernyataan SPD dalam PP.", "Evaluator memeriksa deskripsi aset, ancaman, OSP, dan asumsi apakah terdefinisi lengkap, relevan, dan tidak ambigu.", "SPD konsisten & bebas kontradiksi"],
        ["APE_OBJ.1", "Security Objectives (Env)", "Sasaran lingkungan operasional.", "Evaluator mengonfirmasi bahwa sasaran lingkungan operasional dapat ditelusuri ke asumsi dan OSP terkait.", "Traceability asumsi valid"],
        ["APE_OBJ.2", "Security Objectives (TOE)", "Sasaran keamanan TOE & lingkungan.", "Evaluator memeriksa rasionalisasi kecukupan bahwa seluruh sasaran bersama-sama memitigasi seluruh ancaman SPD.", "Semua ancaman termitigasi tuntas"],
        ["APE_ECD.1", "Extended Components Def.", "Definisi komponen perluasan.", "Evaluator memastikan setiap komponen perluasan memiliki struktur D, C, E yang benar dan tidak menduplikasi komponen standar.", "Taksonomi perluasan valid"],
        ["APE_REQ.1", "Stated Requirements", "Kebutuhan keamanan yang dinyatakan.", "Evaluator memeriksa seluruh operasi SFR/SAR dan memverifikasi tidak ada operasi yang menggantung atau keliru.", "Operasi selesai & benar"],
        ["APE_REQ.2", "Derived Requirements", "Rasionalisasi kebutuhan keamanan.", "Evaluator mengonfirmasi keterlacakan dan kecukupan SFR/SAR dalam memenuhi seluruh sasaran keamanan TOE.", "Traceability SFR -> Obj valid"]
    ]
    create_table(t2_2_widths, t2_2_aligns, t2_2_headers, t2_2_data)

    # Tabel 2.3: Kelas ACE
    add_h2("3.3 Kriteria Evaluasi Kelas ACE (PP-Configuration Evaluation - Klausul 10)")
    add_body(
        "Kelas ACE memverifikasi keutuhan, kompatibilitas, dan konsistensi gabungan Base PP dan PP-Module dalam konfigurasi terintegrasi."
    )

    t2_3_headers = ["Sub-Aktivitas", "Komponen Evaluasi", "Objek Bukti Evaluasi", "Fokus Unit Kerja Evaluator (Work Units)", "Kriteria Putusan PASS"]
    t2_3_widths = [1.0, 1.4, 1.5, 2.1, 0.7]
    t2_3_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t2_3_data = [
        ["ACE_INT.1", "PP-Module Introduction", "Dokumen PP-Module.", "Evaluator memeriksa identifikasi modul dan kejelasan relasi fungsional terhadap Base PP.", "Modul teridentifikasi unik"],
        ["ACE_CCL.1", "PP-Module Conformance", "Klaim konformansi modul.", "Evaluator mengonfirmasi kepatuhan modul terhadap persyaratan tipe konformansi Base PP.", "Klaim kompatibel"],
        ["ACE_SPD.1", "PP-Module SPD", "SPD tambahan dalam modul.", "Evaluator memeriksa bahwa ancaman/OSP tambahan hanya berlaku untuk lingkup fitur modul.", "Lingkup SPD modular valid"],
        ["ACE_OBJ.1/2", "PP-Module Objectives", "Sasaran keamanan modul.", "Evaluator memverifikasi bahwa sasaran modul tidak mereduksi atau membatalkan sasaran Base PP.", "Tidak ada degradasi sasaran"],
        ["ACE_ECD.1", "PP-Module ECD", "Komponen perluasan modul.", "Evaluator memeriksa definisi komponen perluasan baru spesifik pada modul tersebut.", "Format taksonomi modular valid"],
        ["ACE_REQ.1/2", "PP-Module Requirements", "SFR/SAR spesifik modul.", "Evaluator memeriksa penyelesaian operasi dan konsistensi dependensi internal modul.", "Operasi SFR modul tuntas"],
        ["ACE_MCO.1", "PP-Module Consistency", "Analisis konsistensi modul-base.", "Evaluator meneliti secara komparatif bahwa tidak ada benturan kebijakan atau dependensi sirkular antara modul dan base.", "Bebas konflik modul-base"],
        ["ACE_CCO.1", "Configuration Consistency", "Dokumen PP-Configuration lengkap.", "Evaluator menguji keutuhan konfigurasi gabungan, memastikan sistem gabungan membentuk baseline keamanan harmonis.", "Konfigurasi utuh & kohesif"]
    ]
    create_table(t2_3_widths, t2_3_aligns, t2_3_headers, t2_3_data)

    # Tabel 2.4: Kelas ASE
    add_h2("3.4 Kriteria Evaluasi Kelas ASE (Security Target Evaluation - Klausul 11)")
    add_body(
        "Kelas ASE memverifikasi kualitas dokumen Security Target (ST) spesifik produk yang menjadi kontrak hukum dan teknis evaluasi TOE."
    )

    t2_4_headers = ["Sub-Aktivitas", "Komponen ASE", "Fokus Telaah Evaluasi", "Rincian Tindakan Evaluator (Work Units)", "Kriteria Putusan PASS"]
    t2_4_widths = [1.0, 1.3, 1.6, 2.1, 0.7]
    t2_4_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t2_4_data = [
        ["ASE_INT.1", "ST Introduction", "Identifikasi ST, TOE, & Overview", "Evaluator memastikan identifikasi ST/TOE presisi hingga nomor build dan deskripsi operasional tidak bertentangan dengan bukti lain.", "Identifikasi TOE akurat & unik"],
        ["ASE_CCL.1", "Conformance Claims", "Klaim standar & kepatuhan PP", "Evaluator memverifikasi keabsahan klaim standar CC, klaim paket jaminan, dan kepatuhan terhadap PP yang diacu.", "Klaim konformansi valid"],
        ["ASE_SPD.1", "Security Problem Def.", "Ancaman, OSP, dan Asumsi ST", "Evaluator menelaah kelengkapan SPD, memastikan asumsi lingkungan realistis dan batasan TOE digambarkan tegas.", "SPD produk realistis & utuh"],
        ["ASE_OBJ.1/2", "Security Objectives", "Sasaran TOE dan Lingkungan ST", "Evaluator memeriksa keterlacakan dan kecukupan rasionalisasi sasaran terhadap SPD produk nyata.", "Semua ancaman produk terjawab"],
        ["ASE_ECD.1", "Extended Components", "Definisi komponen kustom ST", "Evaluator memeriksa validitas komponen perluasan yang digunakan dalam ST (jika ada).", "Taksonomi ECD valid"],
        ["ASE_REQ.1/2", "Security Requirements", "Operasi SFR & SAR produk", "Evaluator memastikan seluruh operasi (assignment, selection, refinement, iteration) telah diselesaikan dengan benar.", "Operasi tuntas & dependensi terpenuhi"],
        ["ASE_TSS.1", "TOE Summary Spec.", "Deskripsi mekanisme TSF dasar", "Evaluator memeriksa bahwa setiap SFR yang diklaim memiliki deskripsi implementasi mekanisme keamanan di bab TSS.", "Semua SFR terpetakan ke fungsi TSF"],
        ["ASE_TSS.2", "TOE Summary Spec. (Adv)", "Deskripsi arsitektur & konsistensi", "Evaluator memverifikasi bahwa deskripsi TSS konsisten dengan spesifikasi fungsional dan arsitektur pengembang.", "Konsisten dengan desain nyata"],
        ["ASE_COMP.1", "Composite ST Consistency", "Konsistensi ST produk komposit", "Evaluator memeriksa kompatibilitas antara ST produk komposit dengan platform dasar yang telah tersertifikasi.", "Harmonis dengan ST platform"]
    ]
    create_table(t2_4_widths, t2_4_aligns, t2_4_headers, t2_4_data)

    # Tabel 2.5: Kelas ADV (Development)
    add_h2("3.5 Kriteria Evaluasi Kelas ADV (Development - Klausul 12)")
    add_body(
        "Kelas ADV mengevaluasi representasi desain TOE mulai dari spesifikasi antarmuka eksternal fungsional, arsitektur keamanan, desain subsistem dan modul, hingga kode sumber implementasi."
    )

    t2_5_headers = ["Sub-Aktivitas", "Komponen ADV", "Level / Cakupan", "Tindakan & Pengujian Evaluator (Work Units)", "Tingkat Kedalaman"]
    t2_5_widths = [1.0, 1.3, 1.4, 2.3, 0.7]
    t2_5_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t2_5_data = [
        ["ADV_ARC.1", "Security Architecture", "Arsitektur Keamanan", "Evaluator menguji deskripsi arsitektur TSF untuk membuktikan 3 prinsip utama: pemisahan domain (domain separation), proteksi mandiri (self-protection), dan ketakterlewatan (non-bypassability).", "Mendalam (EAL2-7)"],
        ["ADV_FSP.1", "Functional Spec.", "Informal (Basic)", "Evaluator memeriksa spesifikasi fungsional antarmuka TSF (TSFI) eksternal dasar untuk mengonfirmasi korespondensi dengan SFR.", "Dasar (EAL1)"],
        ["ADV_FSP.2", "Functional Spec.", "Fully Defined TSFI", "Evaluator meneliti seluruh antarmuka eksternal TSF beserta parameter input, aksi, pesan galat, dan status pengembalian.", "Sedang (EAL2)"],
        ["ADV_FSP.3", "Functional Spec.", "Complete Details", "Evaluator memeriksa kelengkapan rincian fungsi pendukung (supporting functionality) di seluruh antarmuka TSFI.", "Lengkap (EAL3)"],
        ["ADV_FSP.4", "Functional Spec.", "Complete + Error paths", "Evaluator memverifikasi spesifikasi formal/terinci mencakup jalur penanganan kesalahan lengkap di semua TSFI.", "Tinggi (EAL4)"],
        ["ADV_FSP.5", "Functional Spec.", "Semi-formal Specification", "Evaluator menelaah spesifikasi fungsional berbasis notasi semi-formal presisi tinggi.", "Sangat Tinggi (EAL5)"],
        ["ADV_IMP.1", "Implementation Rep.", "Subset Kode Sumber", "Evaluator meninjau sampel representasi implementasi (kode sumber / skema sirkuit) untuk memverifikasi kesesuaian dengan desain.", "Tinggi (EAL4)"],
        ["ADV_IMP.2", "Implementation Rep.", "Seluruh Kode Sumber", "Evaluator memeriksa keseluruhan kode sumber TSF untuk mendeteksi kerentanan tersembunyi, logika berbahaya, atau ketidaksesuaian.", "Menyeluruh (EAL5-7)"],
        ["ADV_INT.1-3", "TSF Internals", "Modularitas & Kohesi", "Evaluator menganalisis struktur internal TSF untuk mengonfirmasi arsitektur modular, kopling rendah (low coupling), dan kohesi tinggi (high cohesion).", "Arsitektural (EAL4-7)"],
        ["ADV_SPM.1", "Formal Security Model", "Model Kebijakan Formal", "Evaluator memverifikasi pembuktian matematis bahwa model kebijakan keamanan konsisten dan mengontrol semua operasi TSF.", "Formal (EAL6-7)"],
        ["ADV_TDS.1-5", "TOE Design", "Subsistem hingga Modul", "Evaluator menelaah dekomposisi desain dari level subsistem (TDS.1-2) hingga ke level modul dan deskripsi algoritma internal (TDS.3-5).", "Bertingkat (EAL2-7)"],
        ["ADV_COMP.1", "Composite Design", "Kepatuhan Desain Komposit", "Evaluator memeriksa integrasi antarmuka antara aplikasi TOE dan platform dasar yang telah tersertifikasi.", "Komposit"]
    ]
    create_table(t2_5_widths, t2_5_aligns, t2_5_headers, t2_5_data)

    # Tabel 2.6: Kelas AGD (Guidance Documents)
    add_h2("3.6 Kriteria Evaluasi Kelas AGD (Guidance Documents - Klausul 13)")
    add_body(
        "Kelas AGD mengevaluasi kejelasan, kelengkapan, dan kepraktisan dokumen panduan bagi pengguna dan administrator guna mencegah kesalahan konfigurasi operasional."
    )

    t2_6_headers = ["Sub-Aktivitas", "Jenis Panduan", "Sasaran Pengguna", "Kriteria Evaluasi & Tindakan Evaluator (Work Units)", "Kriteria Kualitas"]
    t2_6_widths = [1.0, 1.4, 1.4, 2.2, 0.7]
    t2_6_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t2_6_data = [
        ["AGD_OPE.1", "Panduan Operasional (Operational Guidance)", "Administrator & Pengguna Akhir", "Evaluator memeriksa bahwa panduan mendeskripsikan seluruh antarmuka operasional, peringatan keamanan, rekomendasi konfigurasi aman, dan panduan penanganan insiden tanpa mengandung celah keamanan.", "Jelas & Bebas Ambiguitas"],
        ["AGD_PRE.1", "Prosedur Persiapan (Preparative Procedures)", "Personel Instalasi & Auditor", "Evaluator mempraktikkan langsung prosedur instalasi, verifikasi keaslian paket (cryptographic hash/signature), dan konfigurasi awal TOE untuk mengonfirmasi bahwa status aman tercapai tanpa kompromi.", "Dapat Direplikasi 100%"]
    ]
    create_table(t2_6_widths, t2_6_aligns, t2_6_headers, t2_6_data)

    # Tabel 2.7: Kelas ALC (Life Cycle Support)
    add_h2("3.7 Kriteria Evaluasi Kelas ALC (Life Cycle Support - Klausul 14)")
    add_body(
        "Kelas ALC mengevaluasi kontrol dan keamanan lingkungan pengembangan, manajemen konfigurasi, prosedur pengiriman, dan remediasi kerentanan produk selama siklus hidupnya."
    )

    t2_7_headers = ["Sub-Aktivitas", "Keluarga ALC", "Fokus Pengawasan", "Tindakan & Audit Evaluator (Work Units)", "Level EAL Terkait"]
    t2_7_widths = [1.0, 1.3, 1.5, 2.2, 0.7]
    t2_7_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t2_7_data = [
        ["ALC_CMC.1-5", "CM Capabilities", "Sistem Manajemen Konfigurasi", "Evaluator mengaudit sistem CM pengembang: pelacakan versi, otorisasi perubahan, otomatisasi pembuatan build produk (build automation), dan rencana pengujian penerimaan.", "EAL1 s/d EAL7"],
        ["ALC_CMS.1-5", "CM Scope", "Cakupan Item Konfigurasi", "Evaluator memverifikasi bahwa item CM mencakup tidak hanya kode sumber, tetapi juga dokumentasi desain, alat pengujian, compiler, dan lingkungan perangkat keras.", "EAL1 s/d EAL7"],
        ["ALC_DEL.1", "Delivery Procedures", "Prosedur Pengiriman Aman", "Evaluator meninjau prosedur pengemasan dan transmisi aman TOE ke konsumen untuk mencegah tampering, pembajakan rantai pasok (supply chain attack), atau substitusi produk.", "EAL3 s/d EAL7"],
        ["ALC_DVS.1-2", "Development Security", "Keamanan Fisik & Logis Lab", "Evaluator melakukan audit onsite terhadap fasilitas pengembangan pengembang: kontrol akses fisik, keamanan jaringan internal, latar belakang staf, dan pencegahan kebocoran data.", "EAL3 (DVS.1), EAL5 (DVS.2)"],
        ["ALC_FLR.1-3", "Flaw Remediation", "Remediasi Cacat / Kerentanan", "Evaluator memeriksa prosedur penanganan laporan bug dari pihak luar, pelacakan kerentanan keamanan, serta pembuatan dan distribusi patch keamanan.", "Augmentasi EAL"],
        ["ALC_LCD.1-2", "Life Cycle Model", "Model Siklus Hidup", "Evaluator memverifikasi bahwa model siklus hidup pengembangan terdokumentasi, terukur, dan dipatuhi secara disiplin selama fase rekayasa produk.", "EAL4 s/d EAL7"],
        ["ALC_TAT.1-3", "Tools & Techniques", "Standar Coding & Tooling", "Evaluator memeriksa standar pengkodean pengembang (coding standards), opsi optimasi compiler, dan alat analisis statis yang digunakan untuk menjamin mutu implementasi.", "EAL4 s/d EAL7"],
        ["ALC_COMP.1", "Integration & Delivery", "Pengiriman Bagian Komposit", "Evaluator memeriksa konsistensi prosedur integrasi komponen pihak ketiga dan verifikasi integritas saat pengiriman produk komposit.", "Komposit"]
    ]
    create_table(t2_7_widths, t2_7_aligns, t2_7_headers, t2_7_data)

    # Tabel 2.8: Kelas ATE (Tests)
    add_h2("3.8 Kriteria Evaluasi Kelas ATE (Tests - Klausul 15)")
    add_body(
        "Kelas ATE mengevaluasi pengujian fungsional yang dilakukan oleh pengembang serta mewajibkan evaluator melakukan pengujian mandiri dan independen."
    )

    t2_8_headers = ["Sub-Aktivitas", "Keluarga ATE", "Cakupan Pengujian", "Tindakan Pengujian Evaluator (Work Units)", "Tingkat Independensi"]
    t2_8_widths = [1.0, 1.3, 1.4, 2.3, 0.7]
    t2_8_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t2_8_data = [
        ["ATE_COV.1-3", "Test Coverage", "Cakupan Antarmuka TSFI", "Evaluator menganalisis matriks cakupan uji pengembang untuk memastikan setiap antarmuka TSFI eksternal telah diuji secara menyeluruh.", "Audit Evaluator"],
        ["ATE_DPT.1-3", "Test Depth", "Kedalaman Desain", "Evaluator memeriksa pengujian hingga tingkat subsistem internal (DPT.1-2) dan modul internal (DPT.3) untuk memastikan kebenaran interaksi komponen dalam.", "Audit Evaluator"],
        ["ATE_FUN.1-2", "Functional Tests", "Eksekusi Uji Fungsional", "Evaluator meninjau rencana uji, prosedur uji, dan rekaman hasil uji aktual pengembang untuk memastikan seluruh skenario normal dan kesalahan telah diuji.", "Verifikasi Hasil"],
        ["ATE_IND.1", "Independent Testing", "Sampling Uji Developer", "Evaluator mengeksekusi langsung sampel uji fungsional pengembang di laboratorium evaluasi untuk memverifikasi konsistensi hasil uji.", "Uji Independen Parsial"],
        ["ATE_IND.2", "Independent Testing", "Uji Mandiri Evaluator", "Evaluator merancang rangkaian uji coba independen baru (test suite mandiri) yang belum dilakukan oleh pengembang untuk menguji batasan kritis TSF.", "Uji Mandiri Penuh"],
        ["ATE_COMP.1", "Composite Testing", "Uji Fungsional Komposit", "Evaluator melakukan pengujian terhadap antarmuka komposit antara aplikasi dan platform dasar untuk memastikan integrasi berjalan sempurna.", "Uji Integrasi"]
    ]
    create_table(t2_8_widths, t2_8_aligns, t2_8_headers, t2_8_data)

    # Tabel 2.9: Kelas AVA (Vulnerability Assessment) & Attack Potential
    add_h2("3.9 Kriteria Evaluasi Kelas AVA (Vulnerability Assessment - Klausul 16 dan Annex B)")
    add_body(
        "Kelas AVA mewajibkan evaluator melakukan analisis kerentanan sistematis dan uji penetrasi independen (penetration testing) berdasarkan metrik potensi serangan (Attack Potential)."
    )

    t2_9_headers = ["Sub-Aktivitas", "Tingkat Resistensi", "Fokus Penilaian Kerentanan (CEM Klausul 16)", "Kebutuhan Pengujian Penetrasi", "Target EAL"]
    t2_9_widths = [1.0, 1.3, 2.3, 1.4, 0.7]
    t2_9_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t2_9_data = [
        ["AVA_VAN.1", "No Rating (Basic)", "Evaluator melakukan survei literatur publik untuk menemukan kerentanan umum pada teknologi TOE.", "Uji penetrasi dasar terhadap kelemahan publik.", "EAL1"],
        ["AVA_VAN.2", "Basic", "Evaluator mencari kerentanan publik dan menganalisis dokumentasi desain dasar untuk merancang uji penetrasi.", "Uji penetrasi terhadap penyerang berkeahlian dasar (Basic).", "EAL2, EAL3"],
        ["AVA_VAN.3", "Enhanced-Basic", "Evaluator melakukan analisis kerentanan metodis terhadap representasi desain lengkap dan arsitektur keamanan.", "Uji penetrasi terstruktur terhadap penyerang Enhanced-Basic.", "EAL4"],
        ["AVA_VAN.4", "Moderate", "Evaluator meneliti kode sumber, desain detail, dan analisis independen mendalam untuk menemukan celah non-publik.", "Uji penetrasi intensif terhadap penyerang tingkat Moderate.", "EAL5"],
        ["AVA_VAN.5", "High", "Evaluator melakukan analisis komprehensif seluruh kode sumber dan hardware untuk eksploitasi canggih (side-channel, fault injection).", "Uji penetrasi tingkat tinggi terhadap penyerang setara badan intelijen (High).", "EAL6, EAL7"],
        ["AVA_COMP.1", "Composite Assessment", "Evaluator menganalisis kerentanan baru yang muncul akibat interaksi antara aplikasi TOE dan platform dasar.", "Uji penetrasi komposit pada antarmuka gabungan.", "Komposit"]
    ]
    create_table(t2_9_widths, t2_9_aligns, t2_9_headers, t2_9_data)

    # Tabel 2.9b: Matriks Perhitungan Potensi Serangan
    add_h3("Tabel 2.9b: Matriks Penilaian Faktor Potensi Serangan (Attack Potential Scoring Matrix — Annex B ISO 18045)")
    add_body(
        "Evaluator menghitung nilai numerik potensi serangan yang diperlukan untuk mengidentifikasi dan mengeksploitasi kerentanan berdasarkan 5 faktor terstandarisasi:"
    )

    t2_9b_headers = ["Faktor Penilaian", "Parameter / Kondisi Serangan", "Bobot Identifikasi", "Bobot Eksploitasi", "Keterangan Evaluator"]
    t2_9b_widths = [1.3, 1.6, 1.1, 1.1, 1.6]
    t2_9b_aligns = [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT]
    t2_9b_data = [
        ["Elapsed Time (Waktu)", "<= 1 hari\n<= 1 minggu\n<= 1 bulan\n<= 6 bulan\n> 6 bulan", "0\n1\n2\n3\n5", "0\n0\n1\n2\n3", "Waktu kumulatif yang dibutuhkan penyerang untuk merancang dan mengeksekusi serangan."],
        ["Expertise (Keahlian)", "Layman (Orang awam)\nProficient (Praktisi berpengalaman)\nExpert (Pakar keamanan siber)\nMultiple Experts (Tim pakar multidisiplin)", "0\n1\n2\n5", "0\n0\n1\n3", "Tingkat kompetensi teknis penyerang dalam rekayasa balik, kriptoanalisis, atau pemrograman."],
        ["Knowledge of TOE", "Public (Informasi publik)\nRestricted (Informasi terbatas)\nSensitive (Dokumentasi desain internal)\nCritical (Kode sumber / skema perangkat keras)", "0\n2\n3\n5", "0\n1\n2\n3", "Tingkat kerahasiaan informasi internal TOE yang dibutuhkan untuk melancarkan serangan."],
        ["Window of Opportunity", "Uncontrolled (Akses fisik/logis bebas)\nControlled (Akses dibatasi kontrol operasional)\nDifficult (Akses sangat terbatas / jarang)\nNone (Tidak ada akses yang memungkinkan)", "0\n1\n2\nN/A", "0\n1\n3\nN/A", "Tingkat kemudahan memperoleh akses fisik atau logis ke TOE selama serangan berlangsung."],
        ["Equipment (Peralatan)", "Standard (Komputer & software umum)\nSpecialized (Alat uji osiloskop/logic analyzer)\nBespoke (Alat laboratorium riset khusus/custom)", "0\n1\n2", "0\n1\n2", "Tingkat kecanggihan perangkat keras/lunak yang diperlukan untuk mengeksekusi eksploitasi."]
    ]
    create_table(t2_9b_widths, t2_9b_aligns, t2_9b_headers, t2_9b_data)

    # Tabel 2.9c: Ambang Batas Potensi Serangan
    add_h3("Tabel 2.9c: Ambang Batas Nilai Potensi Serangan (Attack Potential Thresholds)")
    t2_9c_headers = ["Rentang Skor Kumulatif", "Tingkat Ketahanan (Attack Potential Rating)", "Komponen AVA_VAN Terkait", "Interpretasi Kepatuhan Keamanan"]
    t2_9c_widths = [1.5, 1.7, 1.4, 2.1]
    t2_9c_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT]
    t2_9c_data = [
        ["0 — 15 poin", "No rating / Basic", "AVA_VAN.1, AVA_VAN.2", "TOE rentan terhadap serangan penyerang kasual dengan alat umum. Lulus untuk EAL1-EAL3."],
        ["16 — 20 poin", "Enhanced-Basic", "AVA_VAN.3", "TOE tahan terhadap penyerang terampil dengan sumber daya terbatas. Standar wajib EAL4."],
        ["21 — 25 poin", "Moderate", "AVA_VAN.4", "TOE tahan terhadap penyerang berpengalaman tinggi dengan peralatan laboratorium. Standar wajib EAL5."],
        [">= 26 poin", "High", "AVA_VAN.5", "TOE memiliki ketahanan tertinggi, mampu menahan serangan tim pakar dengan alat riset canggih. Standar EAL6-EAL7."]
    ]
    create_table(t2_9c_widths, t2_9c_aligns, t2_9c_headers, t2_9c_data)

    # Tabel 2.10: Kelas ACO (Composition)
    add_h2("3.10 Kriteria Evaluasi Kelas ACO (Composition - Klausul 17)")
    add_body(
        "Kelas ACO mendefinisikan tindakan evaluasi khusus untuk sistem yang dibentuk dari komposisi beberapa TOE yang dievaluasi secara independen."
    )

    t2_10_headers = ["Sub-Aktivitas", "Keluarga ACO", "Aspek yang Dievaluasi", "Tindakan Khusus Evaluator (Work Units)", "Tujuan Jaminan"]
    t2_10_widths = [1.0, 1.3, 1.6, 2.1, 0.7]
    t2_10_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER]
    t2_10_data = [
        ["ACO_COR.1", "Composition Rationale", "Rasionalisasi Komposisi", "Evaluator meneliti justifikasi interaksi antar komponen penyusun TOE untuk memastikan tidak ada asumsi yang saling bertentangan.", "Konsistensi Antar Komponen"],
        ["ACO_DEV.1-3", "Development Evidence", "Bukti Desain Antarmuka", "Evaluator memeriksa spesifikasi antarmuka komunikasi dan pertukaran data antar komponen penyusun TOE.", "Kejelasan Antarmuka Gabungan"],
        ["ACO_REL.1-2", "Reliance of Dep. Comp.", "Ketergantungan Komponen", "Evaluator memverifikasi bahwa komponen aplikasi dapat mengandalkan fungsi keamanan yang disediakan komponen platform dasar.", "Keandalan Layanan Dasar"],
        ["ACO_CTT.1-2", "Composed TOE Testing", "Pengujian Sistem Gabungan", "Evaluator menguji secara langsung operasi sistem komposit di titik-titik integrasi antarmuka untuk mendeteksi anomali komunikasi.", "Integritas Operasional"],
        ["ACO_VUL.1-3", "Composition Vuln. Analysis", "Analisis Kerentanan Gabungan", "Evaluator melakukan analisis kerentanan mendalam untuk mengidentifikasi celah keamanan baru yang muncul semata-mata akibat penggabungan komponen.", "Bebas Kerentanan Komposit"]
    ]
    create_table(t2_10_widths, t2_10_aligns, t2_10_headers, t2_10_data)

    # -------------------------------------------------------------
    # BAGIAN III: SINTESIS DAN PEMETAAN KOMPARATIF
    # -------------------------------------------------------------
    add_h1("4. BAGIAN III: SINTESIS DAN PEMETAAN KOMPARATIF KEDUA STANDAR")
    add_body(
        "Bagian ini menghubungkan secara langsung konstruk konseptual ISO/IEC 15408-1:2022 dengan metodologi operasional ISO/IEC 18045:2026, serta menyajikan panduan implementasi praktis untuk produk 'Secure Vault'."
    )

    # Tabel 3.1: Matriks Korelasi Konstruk Kriteria terhadap Metodologi Evaluasi
    add_h2("4.1 Matriks Korelasi Konstruk Kriteria (ISO/IEC 15408-1) terhadap Metodologi Evaluasi (ISO/IEC 18045)")
    t3_1_headers = ["Klausul ISO/IEC 15408-1:2022", "Konstruk Kriteria Konseptual", "Kelas / Klausul ISO/IEC 18045:2026", "Tindakan Metodologis Evaluator (CEM)", "Artefak Pembuktian"]
    t3_1_widths = [1.2, 1.4, 1.3, 1.6, 1.2]
    t3_1_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT]
    t3_1_data = [
        ["Klausul 6 & 7", "Model Umum, SPD & Sasaran Keamanan", "Klausul 9 (APE), 10 (ACE), 11 (ASE)", "Evaluator memeriksa keterlacakan SPD -> Sasaran -> Kebutuhan dan validitas rasionalisasi.", "ST/PP Dokumen, Matriks Traceability"],
        ["Klausul 8", "Struktur Taksonomi & Operasi Kebutuhan", "Sub-aktivitas *_REQ.1 dan *_REQ.2", "Evaluator mengonfirmasi bahwa seluruh assignment, selection, refinement, dan iteration valid dan lengkap.", "Tabel Pernyataan SFR/SAR dalam ST"],
        ["Klausul 9", "Assurance Packages (EAL1 - EAL7)", "Klausul 8.4 & Seluruh Bab 9-17", "Evaluator mengeksekusi sub-aktivitas yang dipetakan persis untuk setiap level EAL target.", "Work Unit Evaluation Records"],
        ["Klausul 10", "Protection Profiles & Conformance", "Klausul 9 (Kelas APE)", "Evaluator memvalidasi kepatuhan PP terhadap struktur standar dan kelayakan klaim konformansi.", "Evaluation Report for PP"],
        ["Klausul 11", "Modular Construction (Module & Config)", "Klausul 10 (Kelas ACE)", "Evaluator menguji konsistensi modular (ACE_MCO) dan konfigurasi gabungan (ACE_CCO).", "Evaluation Report for PP-Config"],
        ["Klausul 12", "Security Target & Direct Rationale", "Klausul 11 (Kelas ASE)", "Evaluator meneliti konsistensi TSS dan memvalidasi keabsahan rasionalisasi langsung SPD -> SFR.", "Evaluation Report for ST"],
        ["Klausul 13", "Evaluation Context & Results", "Klausul 8.2 & 8.5 (Output Task)", "Evaluator menetapkan verdict (PASS/FAIL/INCONCLUSIVE) dan menyusun laporan ETR akhir.", "Observation Report (OR) & ETR"],
        ["Klausul 14", "Composition of Assurance", "Klausul 17 (ACO) & Metodologi Komposit", "Evaluator memverifikasi dependensi modul (ACO_REL), uji komposit (ACO_CTT), dan kerentanan gabungan.", "Composite Evaluation Report"]
    ]
    create_table(t3_1_widths, t3_1_aligns, t3_1_headers, t3_1_data)

    # Tabel 3.2: Perbandingan Dimensi Spesifikasi vs Metodologi
    add_h2("4.2 Perbandingan Dimensi Spesifikasi (ISO 15408-1) vs Metodologi Eksekusi (ISO 18045)")
    t3_2_headers = ["Dimensi Perbandingan", "ISO/IEC 15408-1:2022 (Common Criteria Part 1)", "ISO/IEC 18045:2026 (CEM Methodology)", "Sinergi Operasional"]
    t3_2_widths = [1.4, 2.0, 2.0, 1.3]
    t3_2_aligns = [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT]
    t3_2_data = [
        ["Fokus Utama", "Mendefinisikan 'APA' kriteria, model konseptual, taksonomi, dan struktur artefak keamanan.", "Mendefinisikan 'BAGAIMANA' evaluator melakukan verifikasi teknis dan pengujian di lab.", "Saling melengkapi (Spesifikasi vs Metodologi)."],
        ["Pengguna Utama", "Pengembang TOE, penulis Protection Profile, perumus Security Target, analis keamanan.", "Evaluator laboratorium penguji independen dan asesor badan sertifikasi (Certifiers).", "Bahasa kerja bersama antara pembuat dan penguji."],
        ["Satuan Dasar", "Kelas, Keluarga, Komponen, dan Elemen (Developer/Content/Evaluator elements).", "Aktivitas Evaluasi, Sub-aktivitas, Tindakan Evaluator, dan Unit Kerja (Work Units).", "Setiap elemen CC dipetakan ke unit kerja CEM."],
        ["Sifat Ketentuan", "Normatif preskriptif terhadap isi dan struktur dokumen bukti keamanan (evidence).", "Normatif prosedural terhadap langkah verifikasi menggunakan auxiliary verb 'shall'.", "Menjamin konsistensi dan komparabilitas evaluasi."],
        ["Luaran Dokumen", "Dokumen Protection Profile (PP), PP-Configuration, dan Security Target (ST).", "Dokumen Observation Report (OR) dan Evaluation Technical Report (ETR).", "Menghasilkan bukti audit sertifikasi resmi."]
    ]
    create_table(t3_2_widths, t3_2_aligns, t3_2_headers, t3_2_data)

    # Tabel 3.3: Panduan Penerapan Praktis untuk Proyek "Secure Vault"
    add_h2("4.3 Panduan Penerapan Praktis Evaluasi Keamanan untuk Proyek 'Secure Vault'")
    add_body(
        "Berdasarkan analisis kedua standar, tabel berikut menyajikan baseline kriteria evaluasi yang direkomendasikan untuk pengembangan dan sertifikasi produk Secure Vault (brankas data / penyimpanan kunci kriptografi aman)."
    )

    t3_3_headers = ["Domain Evaluasi", "Target / Komponen Relevan", "Kriteria Evaluasi ISO 15408-1", "Metodologi Uji ISO 18045", "Rekomendasi Baseline Secure Vault"]
    t3_3_widths = [1.1, 1.3, 1.5, 1.6, 1.2]
    t3_3_aligns = [WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT]
    t3_3_data = [
        ["Target Jaminan", "EAL4+ (Augmented)", "Memilih paket EAL4 ditambah ALC_FLR.2 (flaw remediation) dan AVA_VAN.4/5.", "Mengeksekusi unit kerja EAL4 penuh ditambah uji penetrasi Moderate/High.", "EAL4+ merupakan standar emas komersial untuk secure storage."],
        ["Kriptografi", "FCS_COP.1, FCS_CKM.1", "Penyelesaian operasi algoritma enkripsi (AES-256-GCM), manajemen kunci, zeroization.", "Evaluator menguji implementasi enkripsi dan pembersihan memori aman saat reset.", "Enkripsi end-to-end data at rest dan data in transit."],
        ["Proteksi Data", "FDP_ACC.1, FDP_ACF.1", "Kebijakan kontrol akses ketat berbasis peran (RBAC) dan atribut keamanan data vault.", "Evaluator mencoba bypass aturan akses menggunakan berbagai akun penguji.", "Pemisahan hak akses multi-user dan multi-tenant."],
        ["Otentikasi", "FIA_UAU.2, FIA_AFL.1", "Otentikasi multifaktor (MFA) sebelum akses data dan penanganan kegagalan otentikasi.", "Evaluator melakukan serangan brute-force dan analisis penguncian akun.", "Proteksi anti brute-force dan time delay bertingkat."],
        ["Proteksi Mandiri", "FPT_FLS.1, ADV_ARC.1", "Fail-secure saat daya mati mendadak, pemisahan domain memori, proteksi tamper.", "Evaluator menguji pemutusan daya tiba-tiba (power glitching) dan integritas memori.", "Arsitektur non-bypassable dan zero-knowledge storage."],
        ["Uji Penetrasi", "AVA_VAN.4 (Moderate)", "Analisis kerentanan terhadap potensi serangan tingkat Moderate (skor 21-25).", "Evaluator melakukan fuzzing antarmuka, uji timing attack, dan ekstraksi memori.", "Verifikasi ketahanan terhadap eksploitasi tingkat tinggi."]
    ]
    create_table(t3_3_widths, t3_3_aligns, t3_3_headers, t3_3_data)

    # -------------------------------------------------------------
    # BAGIAN IV: KESIMPULAN DAN GLOSARIUM
    # -------------------------------------------------------------
    add_h1("5. BAGIAN IV: KESIMPULAN DAN GLOSARIUM")
    
    add_h2("5.1 Kesimpulan Teknis & Strategis")
    add_body(
        "1. Harmonisasi Standar: Evaluasi keamanan yang kredibel dan diakui secara internasional memerlukan pemahaman mendalam atas pembagian peran antara ISO/IEC 15408-1:2022 sebagai standar spesifikasi dan model, dengan ISO/IEC 18045:2026 sebagai standar metodologi eksekusi."
    )
    add_body(
        "2. Paradigma Modern: Edisi terkini membawa efisiensi signifikan melalui konstruksi kebutuhan modular (PP-Module & PP-Configuration), formalisasi exact conformance, format Direct Rationale ST, serta evaluasi komposit yang mempercepat waktu pemasaran produk tanpa mengurangi ketelitian jaminan keamanan."
    )
    add_body(
        "3. Penerapan pada Secure Vault: Untuk produk Secure Vault, kombinasi target jaminan EAL4+ dengan penekanan pada kelas ADV_ARC.1 (arsitektur proteksi mandiri), ADV_FSP.4 (spesifikasi antarmuka lengkap), ALC_DVS.2 (keamanan fasilitas pengembangan), serta AVA_VAN.4 (uji penetrasi moderate) memberikan profil keamanan yang optimal, kokoh, dan siap sertifikasi internasional."
    )

    add_h2("5.2 Glosarium Istilah Teknis Common Criteria dan CEM")
    
    t_glo_headers = ["Istilah / Singkatan", "Istilah Bahasa Inggris", "Definisi Resmi Berdasarkan ISO/IEC 15408-1 & ISO/IEC 18045"]
    t_glo_widths = [1.4, 1.8, 3.5]
    t_glo_aligns = [WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT]
    t_glo_data = [
        ["TOE", "Target of Evaluation", "Entitas perangkat lunak, firmware, dan/atau perangkat keras yang menjadi subjek evaluasi keamanan formal."],
        ["TSF", "TOE Security Functionality", "Himpunan gabungan dari seluruh perangkat keras, perangkat lunak, dan firmware dari TOE yang wajib diandalkan untuk menegakkan kebijakan keamanan."],
        ["TSFI", "TSF Interface", "Antarmuka logis atau fisik yang digunakan untuk berinteraksi dengan TSF, memanggil fungsinya, atau menerima respons darinya."],
        ["SFR", "Security Functional Requirement", "Persyaratan keamanan fungsional yang mendefinisikan perilaku operasional keamanan yang diharapkan dari TOE (diatur dalam ISO/IEC 15408-2)."],
        ["SAR", "Security Assurance Requirement", "Persyaratan jaminan keamanan yang mendefinisikan langkah verifikasi dan pembuktian yang harus diambil untuk memastikan TSF bekerja benar (diatur dalam ISO/IEC 15408-3)."],
        ["PP", "Protection Profile", "Dokumen pernyataan kebutuhan keamanan yang independen dari implementasi tertentu, mendefinisikan baseline keamanan untuk kategori produk TI tertentu."],
        ["PP-Module", "Protection Profile Module", "Pernyataan kebutuhan keamanan modular yang memperluas Base PP untuk fitur atau domain keamanan spesifik."],
        ["PP-Configuration", "PP Configuration", "Kumpulan terdefinisi yang terdiri dari minimal satu Base PP dan minimal satu PP-Module yang dievaluasi sebagai satu kesatuan utuh."],
        ["ST", "Security Target", "Dokumen spesifikasi keamanan spesifik produk yang memuat klaim fungsional dan jaminan untuk produk TOE nyata yang dievaluasi."],
        ["EAL", "Evaluation Assurance Level", "Paket jaminan standar bergradasi (EAL1 hingga EAL7) yang merepresentasikan tingkat ketelitian dan kedalaman pengujian evaluasi."],
        ["CEM", "Common Evaluation Methodology", "Kumpulan prosedur, tindakan minimum evaluator, dan unit kerja terstandarisasi untuk mengevaluasi produk TI berbasis Common Criteria (ISO/IEC 18045)."],
        ["Work Unit", "Evaluation Work Unit", "Aktivitas terkecil yang harus dilaksanakan oleh evaluator dalam suatu sub-aktivitas evaluasi untuk menentukan putusan (verdict)."],
        ["Verdict", "Evaluator Verdict", "Pernyataan putusan resmi yang diberikan oleh evaluator terhadap suatu unit kerja, komponen, atau keseluruhan TOE: PASS, FAIL, atau INCONCLUSIVE."],
        ["Attack Potential", "Attack Potential", "Ukuran upaya, keahlian, waktu, pengetahuan, dan peralatan yang dibutuhkan oleh penyerang untuk mengeksploitasi kerentanan TOE."],
        ["SPD", "Security Problem Definition", "Pernyataan formal mengenai masalah keamanan yang mencakup ancaman, kebijakan keamanan organisasi (OSP), dan asumsi lingkungan."],
        ["Strict Conformance", "Strict Conformance", "Tipe kepatuhan di mana kebutuhan dalam ST harus setara persis atau merupakan subset hierarkis yang lebih ketat dari PP dasar."],
        ["Exact Conformance", "Exact Conformance", "Tipe kepatuhan di mana kebutuhan dalam ST harus 100% identik dengan PP tanpa penambahan atau pengurangan sepihak."],
        ["Direct Rationale ST", "Direct Rationale Security Target", "Format ST alternatif dalam ISO/IEC 15408-1:2022 di mana kebutuhan SFR ditautkan secara langsung ke SPD tanpa sasaran keamanan perantara."],
        ["Non-bypassability", "Non-bypassability", "Sifat arsitektural di mana seluruh akses dan operasi terhadap aset terlindung dijamin selalu melewati pemeriksaan TSF tanpa dapat dihindari."],
        ["Domain Separation", "Domain Separation", "Sifat arsitektural di mana memori dan ruang eksekusi TSF diisolasi secara fisik atau logis dari proses pengguna dan aplikasi luar."],
        ["Self-protection", "Self-protection", "Kemampuan TSF untuk melindungi dirinya sendiri dari manipulasi, penonaktifan, atau intervensi berbahaya dari pihak luar."],
        ["ETR", "Evaluation Technical Report", "Laporan komprehensif yang disusun oleh evaluator berisi seluruh rincian hasil kerja, analisis teknis, dan justifikasi putusan evaluasi."],
        ["OR", "Observation Report", "Laporan perantara yang mencatat temuan defisiensi atau kekurangan bukti evaluasi untuk ditindaklanjuti oleh pengembang."]
    ]
    create_table(t_glo_widths, t_glo_aligns, t_glo_headers, t_glo_data)

    # Save document
    doc.save(filename)
    print(f"Document successfully created and saved at: {os.path.abspath(filename)}")

if __name__ == "__main__":
    create_evaluation_document()
