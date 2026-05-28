#!/usr/bin/env python3
"""
============================================================
provision_esp32.py — Trimite certificatele la ESP32 via Serial
============================================================
Citește fișierele PEM din directorul certs/ și le trimite la
ESP32-ul care rulează sketch-ul de provisioning.

Utilizare:
  python scripts/provision_esp32.py --port COM5

  Sau cu cale personalizată pentru certificate:
  python scripts/provision_esp32.py --port COM5 --certs ./certs

Fișiere așteptate în directorul certs/:
  ca.crt           → root_ca      (CA root NFC-Payment-CA)
  pos-buc-001.crt  → mtls_cert    (Certificat client POS)
  pos-buc-001.key  → mtls_key     (Cheie privată client POS)
  bank_bt_public.pem → bank_pub   (Cheie publică RSA bancă)

Protocolul Serial:
  Script → ESP32:  CERT_KEY\\n + PEM content + <<<END>>>\\n
  ESP32 → Script:  OK:CERT_KEY\\n sau ERR:CERT_KEY:mesaj\\n
============================================================
"""

import argparse
import sys
import time
import os
import serial


# Mapare fișier → cheie NVS
CERT_MAP = {
    "ca.crt":              "root_ca",
    "pos-buc-001.crt":     "mtls_cert",
    "pos-buc-001.key":     "mtls_key",
    "bank_bt_public.pem":  "bank_pub",
}


def wait_for_ready(ser: serial.Serial, timeout: float = 15.0) -> bool:
    """Așteaptă ca ESP32 să trimită 'READY'."""
    start = time.time()
    while time.time() - start < timeout:
        if ser.in_waiting:
            line = ser.readline().decode("utf-8", errors="replace").strip()
            print(f"  ESP32: {line}")
            if line == "READY":
                return True
    return False


def send_cert(ser: serial.Serial, key: str, pem: str) -> bool:
    """Trimite un certificat PEM la ESP32."""
    print(f"\n{'='*50}")
    print(f"  Trimit: {key} ({len(pem)} bytes)")
    print(f"{'='*50}")

    # Trimitem numele cheii
    ser.write(f"{key}\n".encode())
    time.sleep(0.1)

    # Trimitem conținutul PEM linie cu linie
    for line in pem.strip().split("\n"):
        ser.write(f"{line}\n".encode())
        time.sleep(0.01)

    # Trimitem delimitatorul de final
    ser.write(b"<<<END>>>\n")
    time.sleep(0.5)

    # Citim răspunsul
    deadline = time.time() + 10.0
    while time.time() < deadline:
        if ser.in_waiting:
            resp = ser.readline().decode("utf-8", errors="replace").strip()
            print(f"  ESP32: {resp}")
            if resp.startswith(f"OK:{key}"):
                return True
            if resp.startswith(f"ERR:{key}"):
                return False
        time.sleep(0.1)

    print(f"  TIMEOUT: Nu am primit răspuns pentru {key}")
    return False


def send_done(ser: serial.Serial) -> bool:
    """Trimite comanda DONE pentru verificare finală."""
    ser.write(b"DONE\n")
    time.sleep(0.5)

    deadline = time.time() + 5.0
    while time.time() < deadline:
        if ser.in_waiting:
            resp = ser.readline().decode("utf-8", errors="replace").strip()
            print(f"  ESP32: {resp}")
            if resp == "OK:DONE":
                return True
        time.sleep(0.1)
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Provisionare certificate ESP32 via Serial"
    )
    parser.add_argument(
        "--port", required=True,
        help="Portul serial al ESP32 (ex: COM5, /dev/ttyUSB0)"
    )
    parser.add_argument(
        "--baud", type=int, default=115200,
        help="Viteza serial (default: 115200)"
    )
    parser.add_argument(
        "--certs", default=None,
        help="Directorul cu certificatele (default: ./certs relativ la repo root)"
    )
    parser.add_argument(
        "--wipe", action="store_true",
        help="Șterge NVS-ul înainte de provisionare"
    )
    args = parser.parse_args()

    # Determinăm directorul certs
    if args.certs:
        certs_dir = args.certs
    else:
        # Căutăm relativ la scriptul curent
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(script_dir)
        certs_dir = os.path.join(repo_root, "certs")

    print(f"📁 Director certificate: {certs_dir}")

    # Verificăm că toate fișierele necesare există
    missing = []
    for filename in CERT_MAP:
        filepath = os.path.join(certs_dir, filename)
        if not os.path.isfile(filepath):
            missing.append(filename)

    if missing:
        print(f"\n❌ Fișiere lipsă în {certs_dir}:")
        for f in missing:
            print(f"   - {f}")
        print("\nGenerează certificatele cu: python setup.py")
        sys.exit(1)

    # Citim toate certificatele
    certs = {}
    for filename, key in CERT_MAP.items():
        filepath = os.path.join(certs_dir, filename)
        with open(filepath, "r") as f:
            certs[key] = f.read()
        print(f"  ✓ {filename} → {key} ({len(certs[key])} bytes)")

    # Deschidem portul serial
    print(f"\n🔌 Conectare la {args.port} ({args.baud} baud)...")
    try:
        ser = serial.Serial(args.port, args.baud, timeout=1)
    except serial.SerialException as e:
        print(f"❌ Nu pot deschide {args.port}: {e}")
        sys.exit(1)

    time.sleep(2)  # Așteptăm boot-ul ESP32

    # Citim orice output buffered
    while ser.in_waiting:
        line = ser.readline().decode("utf-8", errors="replace").strip()
        print(f"  ESP32: {line}")

    # Așteptăm READY
    print("⏳ Aștept ESP32 READY...")
    if not wait_for_ready(ser, timeout=15.0):
        print("❌ ESP32 nu a trimis READY. Verifică că sketch-ul de "
              "provisioning e flashat.")
        ser.close()
        sys.exit(1)

    print("✅ ESP32 pregătit pentru provisioning.\n")

    # Opțional: wipe NVS
    if args.wipe:
        print("🧹 Se șterge NVS-ul...")
        ser.write(b"WIPE\n")
        time.sleep(1)
        while ser.in_waiting:
            line = ser.readline().decode("utf-8", errors="replace").strip()
            print(f"  ESP32: {line}")

    # Trimitem certificatele
    success = True
    for key in ["root_ca", "mtls_cert", "mtls_key", "bank_pub"]:
        if not send_cert(ser, key, certs[key]):
            print(f"❌ EROARE la trimiterea {key}!")
            success = False
            break

    if success:
        # Verificare finală
        print(f"\n{'='*50}")
        print("  VERIFICARE FINALĂ")
        print(f"{'='*50}")
        send_done(ser)

    ser.close()

    if success:
        print("\n🎉 Provisioning COMPLET!")
        print("   Acum flashează codul principal:")
        print("   cd ESP32_code && pio run --target upload")
    else:
        print("\n❌ Provisioning EȘUAT. Verifică erorile de mai sus.")
        sys.exit(1)


if __name__ == "__main__":
    main()
