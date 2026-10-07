# SpamGuard Studio (Phase 2 + 3)

Node 18+ needed (sirf developer machine par). Non-tech users ke liye Phase 4 mein Mac app banegi.

    npm install
    node bin/sg.js scan  site.zip                         # sirf dekho (kuch badalta nahi)
    node bin/sg.js protect site.zip --out ./result        # protect + backup + report
    node bin/sg.js protect site.zip --dry-run             # dikhao kya badlega, kuch likho mat
    node bin/sg.js protect ./all-sites --bulk --out ./result

Result folder (har site ka): `<site>-protected.zip`, `<site>-backup-original.zip`, `report.txt`, `report.json`, `PRIVATE-login.txt`.
Bulk mein: `summary.csv`, `report.txt`, `PRIVATE-credentials.csv` (ise kisi ko mat bhejo).

Options: `--include-review` (review wale forms bhi), `--sql dump.sql`, `--password`, `--notify mail`, `--quarantine`, `--keep-folder`, `--base-path /sub/`.

Safety rules: original ko kabhi nahi chhuta; sirf lines JODTA hai (kuch delete/rewrite nahi); har badli hui PHP file par `php -l`
(PHP ho to) aur badlav ke baad dobara scan; guard `is_file()` ke andar hai, kit na ho to bhi site chalti rahegi.
Undo: lines `/* SpamGuard:begin */ ... /* SpamGuard:end */` aur `<!-- SpamGuard --><script ...></script>` hata do, ya backup zip upload kar do.

    npm test    # 42 tests, PHP ho to asli PHP server par spam-vs-real bhi chalta hai
