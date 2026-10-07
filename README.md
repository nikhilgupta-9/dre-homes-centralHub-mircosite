# SpamGuard Studio

Micro-site ka zip ya folder dalo, ye usme enquiry forms dhundh kar spam-protection laga deta hai
(protected zip + backup + report). **Sirf Python chahiye. Koi install/DMG/Apple warning nahi.**
Sab kuch aapke computer par chalta hai, browser me khulta hai, kuch internet par nahi jata.

## Chalana (Mac)
1. Terminal kholo (Spotlight me "Terminal").
2. Ye line paste karo:

       curl -L https://github.com/nikhilgupta-9/dre-homes-centralHub-mircosite/archive/refs/heads/main.tar.gz | tar xz && cd dre-homes-centralHub-mircosite-main && python3 studio.py

   (Mac pehli baar "command line tools" install karne ko bol sakta hai: **Install** dabao, 2-5 minute, phir wahi line dobara.)
3. Browser me `http://127.0.0.1:4780` khulega. Zip/folder drag karo, **Protect karo** dabao.
   Result: `Documents/SpamGuard Results/`.

Dobara: `cd dre-homes-centralHub-mircosite-main && python3 studio.py`. Band karna: Ctrl+C.
Windows: folder me `Start.bat` double-click.

## Folders
- `studio.py`: start file. `sgstudio/`: scanner, protector, local web page (Python, stdlib only).
- `kit/spamguard/`: anti-spam PHP kit jo sites me lagta hai (PHP 8.1+ server par chalta hai).
- `pytests/`: tests (`python3 -m unittest discover -s pytests`). `src/`, `test/`: purana Node reference, sirf tests me compare ke kaam aata hai; user ko iski zarurat nahi.
