# ============================================================
# Dockerfile — rețeta pentru construirea containerului Gateway
#
# Un Dockerfile e ca o rețetă de gătit:
# "Ia această bază, adaugă ingredientele, configurează, servește"
#
# Docker citește acest fișier de SUS în JOS și execută
# fiecare instrucțiune pe rând.
# ============================================================


# FROM — punctul de plecare (imaginea de bază)
# În loc să pornim de la zero (sistem de operare gol),
# folosim o imagine oficială Python care are deja Python instalat.
# "3.11-slim" = Python 3.11 pe o versiune minimală de Linux (Debian)
# "slim" înseamnă că nu are tool-uri extra — containerul e mai mic și mai sigur
FROM python:3.11-slim


# WORKDIR — directorul de lucru ÎNĂUNTRUL containerului
# Toate comenzile următoare se vor executa în /app
# E echivalentul cu "cd /app" dar permanent
WORKDIR /app


# COPY — copiază fișiere de pe calculatorul TÂU în container
# Sintaxa: COPY <sursă pe calculatorul tău> <destinație în container>
#
# De ce copiem requirements.txt SEPARAT înainte de restul codului?
# Docker are un sistem de cache inteligent: dacă un layer nu s-a schimbat,
# îl refolosește. requirements.txt se schimbă RAR (doar când adaugi librării).
# Codul se schimbă DES. Astfel, "pip install" nu se mai rulează la fiecare
# modificare de cod — economisim minute la fiecare rebuild!
COPY requirements.txt .


# RUN — execută o comandă în timpul BUILD-ului containerului
# Instalăm toate librăriile din requirements.txt
# --no-cache-dir = nu stoca cache-ul pip în container (economisim spațiu)
RUN pip install --no-cache-dir -r requirements.txt


# COPY . . — acum copiem TOT codul serviciului în container
# Primul "." = tot din folderul services/gateway/ de pe calculatorul tău
# Al doilea "." = în /app din container (WORKDIR setat mai sus)
COPY . .


# EXPOSE — documentează că acest container ascultă pe portul 8003
# ATENȚIE: EXPOSE singur NU deschide portul! E doar documentație.
# Portul real se deschide în docker-compose.yml cu "ports:"
EXPOSE 8003


# CMD — comanda care pornește aplicația când containerul e lansat
# Aceasta e comanda FINALĂ, rulată când faci "docker compose up"
# Traducere: "pornește uvicorn, importă obiectul 'app' din main.py,
# ascultă pe toate interfețele de rețea (0.0.0.0), portul 8003"
#
# "0.0.0.0" e important! Dacă scriem "127.0.0.1" (localhost),
# containerul ascultă doar pe el însuși și nu e accesibil din afară.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8003"]
