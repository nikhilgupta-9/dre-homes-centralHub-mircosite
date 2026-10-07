# SpamGuard Studio (browser version)

Normal software ki tarah: ek baar start karo, **browser me khulta hai**. Koi DMG, koi Apple warning nahi.
Aapki files kahin internet par nahi jaati, sab isi computer par process hoti hain.

## Pehli baar (Mac)
1. **Node.js** install karo: https://nodejs.org -> "LTS" -> .pkg kholo -> Next, Next. (Ye Apple se verified hai, warning nahi aati.)
2. **Terminal** kholo (Spotlight me "Terminal") aur ye ek line paste karke Enter dabao:

       curl -L https://github.com/nikhilgupta-9/dre-homes-centralHub-mircosite/archive/refs/heads/main.tar.gz | tar xz && cd dre-homes-centralHub-mircosite-main && npm install --omit=dev --ignore-scripts && node bin/sg-web.js

   Browser me **http://127.0.0.1:4780** khul jayega.

## Dobara use karna
Terminal me:  `cd dre-homes-centralHub-mircosite-main && node bin/sg-web.js`
(ya folder me `Start.command` double-click; pehli baar Mac poochhe to right-click -> Open)

## Use
1. Site ka **zip** ya **folder** page par drag karo (ya "Zip chuno" / "Folder chuno").
2. **Protect karo** dabao.
3. Result `Documents/SpamGuard Results/` me aata hai: protected zip + backup + report.

Band karna: Terminal me Ctrl+C.
