
## 📌 Descriere proiect

Acest proiect reprezintă un Proof of Concept pentru un sistem de plăți NFC de tip  *closed-loop* , conceput pentru a simula un flux complet de tranzacționare — de la interacțiunea fizică până la autorizarea bancară. Arhitectura este bazată pe microservicii containerizate (Docker), toate rulând pe un singur server, pentru a demonstra clar separarea responsabilităților și interoperabilitatea componentelor.

Sistemul acoperă întregul lanț operațional: comunicația NFC realizată prin hardware dedicat (ESP32 + PN532), procesarea și rutarea cererilor, tokenizarea datelor sensibile și, în final, autorizarea tranzacției. Componenta de securitate este tratată riguros, utilizând semnături criptografice HMAC-SHA256 pentru integritatea mesajelor și transport securizat prin mTLS v1.3. În paralel, un motor de detecție a fraudei analizează tranzacțiile în timp real, folosind un mecanism de scoring ponderat combinat cu decay exponențial pentru a evalua riscul.

Proiectul include și elemente de monitorizare și analiză, integrând un model de supraveghere similar unui sistem SIEM (SOC), capabil să urmărească și să coreleze evenimentele din întreg ecosistemul.

Trebuie menționat că acest PoC își asumă anumite limitări: nu utilizează un HSM pentru managementul cheilor, este vulnerabil la atacuri de tip NFC relay și depinde de conectivitatea Wi-Fi, neavând suport pentru tranzacții offline.

Scopul principal este de a demonstra, într-un mediu controlat, modul în care un sistem modern de plăți poate fi construit, securizat și monitorizat cap-coadă, oferind o bază solidă pentru extindere sau producție.
