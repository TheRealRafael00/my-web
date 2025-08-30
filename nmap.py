import subprocess
import sys

options = []
target = ""

def run_nmap(command):
    try:
        subprocess.run(command, shell=True)
    except KeyboardInterrupt:
        print("\nDihentikan pengguna.")
        sys.exit()

def add_opt(opt):
    options.append(opt)

def main():
    global target
    while True:
        print("\n=== Nmap Wrapper Lengkap ===")
        print("1. Tentukan Target")
        print("2. Mode Scan")
        print("3. Deteksi OS dan Service")
        print("4. Script NSE")
        print("5. Output")
        print("6. Firewall / Evasion")
        print("7. Timing / Performance")
        print("8. Penemuan Host (Host Discovery)")
        print("9. Traceroute / Routing")
        print("10. IPv6")
        print("11. Input Target dari File")
        print("12. Lainnya (Debug, Retry, Timeout, dll)")
        print("13. Tambahkan Opsi Manual")
        print("14. Jalankan Scan")
        print("15. Keluar")

        choice = input("Pilih menu: ")

        if choice == "1":
            target = input("Masukkan target (IP/hostname/range/CIDR/file): ")
        elif choice == "2":
            print("\n--- Mode Scan ---")
            print("1. TCP SYN Stealth (-sS)")
            print("2. TCP Connect (-sT)")
            print("3. UDP Scan (-sU)")
            print("4. TCP Null (-sN)")
            print("5. FIN (-sF)")
            print("6. Xmas (-sX)")
            print("7. ACK (-sA)")
            print("8. Window (-sW)")
            print("9. Maimon (-sM)")
            print("10. SCTP INIT (-sY)")
            print("11. SCTP COOKIE-ECHO (-sZ)")
            print("12. IP Protocol Scan (-sO)")
            print("13. Port spesifik (-p)")
            opt = input("Pilih: ")
            if opt == "1": add_opt("-sS")
            elif opt == "2": add_opt("-sT")
            elif opt == "3": add_opt("-sU")
            elif opt == "4": add_opt("-sN")
            elif opt == "5": add_opt("-sF")
            elif opt == "6": add_opt("-sX")
            elif opt == "7": add_opt("-sA")
            elif opt == "8": add_opt("-sW")
            elif opt == "9": add_opt("-sM")
            elif opt == "10": add_opt("-sY")
            elif opt == "11": add_opt("-sZ")
            elif opt == "12": add_opt("-sO")
            elif opt == "13":
                ports = input("Masukkan port/range: ")
                add_opt(f"-p {ports}")
        elif choice == "3":
            print("\n--- Deteksi ---")
            print("1. OS Detection (-O)")
            print("2. Aggressive OS Guess (--osscan-guess)")
            print("3. Service/Version (-sV)")
            print("4. Aggressive Mode (-A)")
            opt = input("Pilih: ")
            if opt == "1": add_opt("-O")
            elif opt == "2": add_opt("--osscan-guess")
            elif opt == "3": add_opt("-sV")
            elif opt == "4": add_opt("-A")
        elif choice == "4":
            script = input("Masukkan nama/kategori script NSE: ")
            add_opt(f"--script {script}")
            args = input("Tambahkan script-args? (y/n): ")
            if args.lower() == "y":
                sa = input("Masukkan args: ")
                add_opt(f"--script-args {sa}")
        elif choice == "5":
            print("\n--- Output ---")
            print("1. Normal (-oN)")
            print("2. XML (-oX)")
            print("3. Grepable (-oG)")
            print("4. Semua format (-oA)")
            print("5. Verbose (-v)")
            print("6. Debug (-d)")
            opt = input("Pilih: ")
            file = ""
            if opt in ["1","2","3","4"]:
                file = input("Nama file output: ")
            if opt == "1": add_opt(f"-oN {file}")
            elif opt == "2": add_opt(f"-oX {file}")
            elif opt == "3": add_opt(f"-oG {file}")
            elif opt == "4": add_opt(f"-oA {file}")
            elif opt == "5": add_opt("-v")
            elif opt == "6": add_opt("-d")
        elif choice == "6":
            print("\n--- Firewall/Evasion ---")
            print("1. Fragment Packet (-f)")
            print("2. MTU (--mtu)")
            print("3. Data Length (--data-length)")
            print("4. Decoy (-D)")
            print("5. Spoof IP (-S)")
            print("6. Spoof MAC (--spoof-mac)")
            print("7. Source Port (-g)")
            print("8. Badsum (--badsum)")
            opt = input("Pilih: ")
            if opt == "1": add_opt("-f")
            elif opt == "2": add_opt("--mtu " + input("MTU: "))
            elif opt == "3": add_opt("--data-length " + input("Length: "))
            elif opt == "4": add_opt("-D " + input("Decoys: "))
            elif opt == "5": add_opt("-S " + input("IP: "))
            elif opt == "6": add_opt("--spoof-mac " + input("MAC: "))
            elif opt == "7": add_opt("-g " + input("Port: "))
            elif opt == "8": add_opt("--badsum")
        elif choice == "7":
            print("\n--- Timing/Performance ---")
            print("1. -T0 (Paranoid)")
            print("2. -T1 (Sneaky)")
            print("3. -T2 (Polite)")
            print("4. -T3 (Normal)")
            print("5. -T4 (Aggressive)")
            print("6. -T5 (Insane)")
            print("7. Min/Max Rate")
            print("8. Min/Max Parallelism")
            print("9. Max Retries (--max-retries)")
            print("10. Host Timeout (--host-timeout)")
            opt = input("Pilih: ")
            if opt in ["1","2","3","4","5","6"]: add_opt(f"-T{opt[1]}")
            elif opt == "7":
                mn = input("min-rate: ")
                mx = input("max-rate: ")
                if mn: add_opt(f"--min-rate {mn}")
                if mx: add_opt(f"--max-rate {mx}")
            elif opt == "8":
                mn = input("min-parallelism: ")
                mx = input("max-parallelism: ")
                if mn: add_opt(f"--min-parallelism {mn}")
                if mx: add_opt(f"--max-parallelism {mx}")
            elif opt == "9":
                r = input("Max retries: ")
                add_opt(f"--max-retries {r}")
            elif opt == "10":
                t = input("Timeout (ms/s/m): ")
                add_opt(f"--host-timeout {t}")
        elif choice == "8":
            print("\n--- Host Discovery ---")
            print("1. ICMP Echo (-PE)")
            print("2. ICMP Timestamp (-PP)")
            print("3. ICMP Netmask (-PM)")
            print("4. TCP SYN Ping (-PS)")
            print("5. TCP ACK Ping (-PA)")
            print("6. UDP Ping (-PU)")
            print("7. ARP Ping (-PR)")
            print("8. No Ping (-Pn)")
            opt = input("Pilih: ")
            if opt == "1": add_opt("-PE")
            elif opt == "2": add_opt("-PP")
            elif opt == "3": add_opt("-PM")
            elif opt == "4": add_opt("-PS " + input("Port: "))
            elif opt == "5": add_opt("-PA " + input("Port: "))
            elif opt == "6": add_opt("-PU " + input("Port: "))
            elif opt == "7": add_opt("-PR")
            elif opt == "8": add_opt("-Pn")
        elif choice == "9":
            print("\n--- Traceroute / Routing ---")
            print("1. Aktifkan traceroute (--traceroute)")
            opt = input("Pilih: ")
            if opt == "1": add_opt("--traceroute")
        elif choice == "10":
            add_opt("-6")
        elif choice == "11":
            print("\n--- Input Target dari File ---")
            print("1. -iL <file>")
            print("2. -iR <num>")
            opt = input("Pilih: ")
            if opt == "1": add_opt("-iL " + input("Nama file: "))
            elif opt == "2": add_opt("-iR " + input("Jumlah: "))
        elif choice == "12":
            print("\n--- Lainnya ---")
            print("1. Aggressive Scan Delay (--scan-delay)")
            print("2. Max Scan Delay (--max-scan-delay)")
            print("3. Top Ports (--top-ports)")
            print("4. Fast Scan (-F)")
            print("5. Paket khusus (--data-string/--data-length)")
            opt = input("Pilih: ")
            if opt == "1": add_opt("--scan-delay " + input("Delay ms: "))
            elif opt == "2": add_opt("--max-scan-delay " + input("Delay ms: "))
            elif opt == "3": add_opt("--top-ports " + input("Jumlah port: "))
            elif opt == "4": add_opt("-F")
            elif opt == "5":
                ds = input("Data string: ")
                if ds: add_opt(f"--data-string {ds}")
        elif choice == "13":
            cmd = input("Masukkan opsi manual: ")
            add_opt(cmd)
        elif choice == "14":
            if not target:
                target = input("Masukkan target: ")
            full_cmd = f"nmap {' '.join(options)} {target}"
            print("\nPerintah dijalankan:\n", full_cmd)
            run_nmap(full_cmd)
        elif choice == "15":
            sys.exit("Keluar.")
        else:
            print("Pilihan tidak valid.")

if __name__ == "__main__":
    main()
