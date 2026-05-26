#!/usr/bin/env python3
# setup.py - Script de configurare automata cross-platform pentru NFC Payment PoC
#
# Acest script configureaza complet mediul de rulare pe orice masina (Windows, macOS, Linux):
#   1. Copiaza .env.EXAMPLE in .env (daca nu exista).
#   2. Sterge folderele goale create gresit de Docker in ./certs/ (daca utilizatorul a rulat inainte docker compose).
#   3. Converteste sfarsiturile de rand (CRLF -> LF) pentru scripturile de Linux (SH/SQL).
#   4. Ruleaza un container Docker temporar pentru a genera toate certificatele mTLS si cheile private.
#   5. Opreste si curata eventuale containere orfane din rulari anterioare.
#
# Cerinte preliminare:
#   - Python 3.x instalat pe calculatorul gazda.
#   - Docker Desktop pornit.

import os
import shutil
import subprocess
import sys

def print_step(message):
    print(f"\n======== {message} ========")

def setup_env():
    print_step("Pasul 1: Configurare variabile de mediu (.env)")
    env_file = ".env"
    env_example = ".env.EXAMPLE"
    
    if os.path.exists(env_file):
        print("  [INFO] Fisierul .env a fost detectat (de exemplu, copiat manual sau de pe USB). Va fi pastrat complet intact.")
    else:
        if os.path.exists(env_example):
            shutil.copy(env_example, env_file)
            print("  [SUCCESS] A fost creat fisierul .env prin copierea .env.EXAMPLE.")
            print("            (Poti edita cheile din .env daca doresti, deei cele default sunt configurate pentru teste).")
        else:
            print(f"  [ERROR] Nu am gasit fisierul {env_example}! Asigura-te ca rulezi scriptul din radacina proiectului.")
            sys.exit(1)

def cleanup_invalid_cert_dirs():
    print_step("Pasul 2: Curatare directoare invalide create de Docker in ./certs/")
    certs_dir = "certs"
    if not os.path.exists(certs_dir):
        os.makedirs(certs_dir)
        print(f"  [INFO] Folderul '{certs_dir}' a fost creat.")
        return

    # Directoarele individuale pe care Docker Desktop le creeaza gresit ca foldere daca fisierele nu existau pe host
    invalid_targets = [
        "bank_bcr_private.pem",
        "bank_bt_private.pem",
        "bank_ing_private.pem",
        "ca.crt",
        "ca.key"
    ]

    cleaned_any = False
    for target in invalid_targets:
        target_path = os.path.join(certs_dir, target)
        if os.path.exists(target_path):
            if os.path.isdir(target_path):
                print(f"  [WARNING] S-a detectat folderul invalid '{target_path}'. Se sterge...")
                try:
                    shutil.rmtree(target_path)
                    print(f"  [SUCCESS] S-a sters folderul invalid: {target_path}")
                    cleaned_any = True
                except Exception as e:
                    print(f"  [ERROR] Nu s-a putut sterge folderul {target_path}: {e}")
            else:
                # Este un fisier valid, nu facem nimic
                pass

    if not cleaned_any:
        print("  [INFO] Nu s-au detectat directoare invalide in folderul 'certs/'. Totul este curat.")

def convert_line_endings():
    print_step("Pasul 3: Conversie sfarsituri de rand in format Unix (CRLF -> LF)")
    
    files_to_convert = [
        os.path.join("certs", "scripts", "generate_certs.sh"),
        os.path.join("db", "init", "bank", "00_create_dbs.sql"),
        os.path.join("db", "init", "bank", "01_schema.sh"),
        os.path.join("db", "init", "bank", "01_schema.sql.template"),
        os.path.join("db", "init", "tsp", "01_schema.sql")
    ]

    for file_path in files_to_convert:
        if os.path.exists(file_path):
            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                
                # Inlocuim \r\n (Windows) cu \n (Unix)
                unix_content = content.replace(b"\r\n", b"\n")
                
                if unix_content != content:
                    with open(file_path, "wb") as f:
                        f.write(unix_content)
                    print(f"  [SUCCESS] S-au convertit sfarsiturile de rand pentru: {file_path}")
                else:
                    print(f"  [INFO] Fisierul este deja in format Unix: {file_path}")
            except Exception as e:
                print(f"  [ERROR] Eroare la conversia fisierului {file_path}: {e}")
        else:
            print(f"  [WARNING] Fisierul nu a fost gasit pentru conversie: {file_path}")

def generate_certificates():
    print_step("Pasul 4: Generare certificate mTLS si chei private prin Docker")
    
    # Folosim calea absoluta curenta pentru mount in Docker
    cwd = os.getcwd()
    
    # Comanda Docker care porneste un container Alpine, instaleaza openssl si bash,
    # ruleaza scriptul de generare a certificatelor si apoi se opreste.
    docker_cmd = [
        "docker", "run", "--rm",
        "-v", f"{cwd}:/app",
        "-w", "/app",
        "alpine",
        "sh", "-c", "apk add --no-cache openssl bash && bash certs/scripts/generate_certs.sh"
    ]
    
    print("  [INFO] Se lanseaza containerul temporar Alpine pentru generare...")
    print(f"  [RUNNING] {' '.join(docker_cmd)}")
    
    try:
        result = subprocess.run(docker_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        print("\n=== Iesire Generare Certificate ===")
        print(result.stdout)
        print("===================================\n")
        print("  [SUCCESS] Toate certificatele mTLS si cheile private au fost generate cu succes in ./certs/!")
    except subprocess.CalledProcessError as e:
        print("\n  [ERROR] Esec la generarea certificatelor prin Docker!")
        print("=== Eroare standard (Stderr) ===")
        print(e.stderr)
        print("=== Iesire standard (Stdout) ===")
        print(e.stdout)
        print("================================")
        sys.exit(1)
    except FileNotFoundError:
        print("  [ERROR] Comanda 'docker' nu a fost gasita! Asigura-te ca Docker Desktop este instalat si ruleaza.")
        sys.exit(1)

def cleanup_stale_containers():
    print_step("Pasul 5: Oprire si curatare containere orfane sau volume vechi")
    
    # 1. Stergere containere vechi orfane din versiuni anterioare (care puteau bloca porturile sau retelele)
    stale_containers = ["nfc-issuing-bank", "nfc-issuing-bank-b"]
    for container in stale_containers:
        check_cmd = ["docker", "ps", "-a", "--filter", f"name={container}", "--format", "{{.ID}}"]
        try:
            res = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.stdout.strip():
                print(f"  [WARNING] S-a detectat containerul orfan '{container}'. Se forteaza stergerea...")
                subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"  [SUCCESS] S-a sters containerul orfan: {container}")
        except Exception:
            pass

    # 2. Oprim si curatam complet volumele actuale ale proiectului pentru a evita scheme de DB lipsa
    print("  [INFO] Se ruleaza 'docker compose down -v' pentru a curata complet volumele si retelele vechi...")
    try:
        subprocess.run(["docker", "compose", "down", "-v"], check=True)
        print("  [SUCCESS] Toate volumele, containerele si retelele vechi au fost curatate complet.")
    except Exception as e:
        print(f"  [WARNING] Nu s-a putut rula docker compose down -v (e normal daca rulezi pentru prima data): {e}")

def main():
    print("=====================================================================")
    print("   NFC PAYMENT PoC - SETUP AUTOMAT PENTRU MASINI NOI / CURATE        ")
    print("=====================================================================")
    
    setup_env()
    cleanup_invalid_cert_dirs()
    convert_line_endings()
    generate_certificates()
    cleanup_stale_containers()
    
    print("\n" + "=" * 69)
    print("[SUCCESS] CONFIGURARE INITIALA FINALIZATA CU SUCCES!")
    print("=" * 69)
    print("Mediul tau este pregatit pentru o pornire complet curata si sigura.")
    print("\nPentru a lansa intreaga suita de 5 microservicii + monitorizare, ruleaza:")
    print("->  docker compose up -d --build")
    print("\nPentru a rula suita completa de teste E2E din Gateway, foloseste:")
    print("->  docker cp tests/e2e_test.py nfc-gateway:/tmp/e2e_test.py")
    print("->  docker exec nfc-gateway python /tmp/e2e_test.py")
    print("=" * 69 + "\n")

if __name__ == "__main__":
    main()
