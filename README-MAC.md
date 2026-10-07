# SpamGuard Studio: Mac app

## 1. .dmg kaise banega (ek baar, Mac ki zarurat nahi)
1. GitHub par ek **private** repo banao aur ye poora folder upload karo.
2. Repo mein **Actions** tab -> **Build Mac app** -> **Run workflow**.
3. 5-10 minute baad run ke andar **SpamGuard-Studio-mac** artifact download karo. Usme `.dmg` hoga (Apple Silicon aur Intel dono par chalta hai).

Mac par khud banana ho: `npm install && npm run dist` (dist/ folder mein .dmg milega).

## 2. Colleagues ke liye install
1. `.dmg` kholo, **SpamGuard Studio** ko **Applications** mein kheench do.
2. Pehli baar: app par **right-click -> Open -> Open**. (App Apple se signed nahi hai, isliye Mac ek baar poochta hai. Sirf pehli baar.)
   Agar phir bhi roke: System Settings -> Privacy & Security -> neeche "Open Anyway".
3. Zip ya folder drag karo, **Protect karo** dabao. Result `Documents/SpamGuard Results/` mein aata hai.

Apple Developer ID ($99/saal) ho to app signed ho sakti hai aur ye warning nahi aayegi.

## 3. Developer ke liye
    npm install          # electron bhi aa jata hai
    npm run app          # app chalao
    npm test             # 47 tests
    npm run test:app     # asli Electron window ko robot se chalata hai (Linux par xvfb chahiye)

Code ka nakshaa: `app/main.js` (window + dialogs), `app/preload.js` (window aur computer ke beech ka chhota pul),
`app/worker.js` (bhaari kaam alag thread mein), `app/renderer/*` (screens), `src/app/service.js` (sab logic, Electron ke bina).
Window ke paas Node nahi hai (contextIsolation + sandbox + CSP). Site ke naam/labels sirf text ki tarah dikhte hain.
