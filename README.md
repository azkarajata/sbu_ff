# Dashboard Freight Forwarder – InJourney Aviation Services

Dashboard 3 unit: **Sales**, **Operation**, **Project Control**.

## Login (demo)
| Username | Password | Unit |
|---|---|---|
| sales | 123 | Sales |
| operation | 123 | Operation |
| projectcontrol | 123 | Project Control |

Login ini hanya di sisi browser (password terlihat di kode), jadi cocok untuk demo, bukan pengamanan data sungguhan.

## Alur
1. Sales kirim RFQ (No. RFQ, perusahaan, POL, POD, deskripsi barang).
2. Operation upload jobsheet cost (PDF/Excel).
3. Sales unduh jobsheet, tambah margin, lalu tandai Deal / Tidak deal.
4. Project Control memantau semua RFQ dan bisa ekspor CSV.

## Deploy ke GitHub Pages
1. Upload `index.html`, `ias_logo.png`, dan `README.md` ke repository.
2. Settings → Pages → Branch `main` / root → Save.
3. Buka `https://<username>.github.io/<repo>/`.

## Catatan penting
Versi ini menyimpan data di `localStorage` browser, jadi data **tidak dibagikan antar pengguna/komputer**.
Untuk dipakai bersama oleh Sales, Operation, dan Project Control, hubungkan ke database (mis. Supabase/Firebase)
dan tambahkan login per unit.
