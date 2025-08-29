import os
import sys
import mimetypes
import subprocess
import zipfile

def detect_hash_type(s):
    length = len(s)
    if all(c in "0123456789abcdef" for c in s.lower()):
        if length == 16: return "LM"
        if length == 32: return "MD5"
        if length == 40: return "SHA1"
        if length == 48: return "NTLM"
        if length == 56: return "SHA224"
        if length == 64: return "SHA256"
        if length == 96: return "SHA384"
        if length == 128: return "SHA512"
    return None

def scan_file(filepath):
    results = []
    try:
        # Deteksi berdasarkan ekstensi
        ext = filepath.lower()
        if zipfile.is_zipfile(filepath):
            with zipfile.ZipFile(filepath, 'r') as zf:
                if any(zinfo.flag_bits & 0x1 for zinfo in zf.infolist()):
                    results.append(("ZIP", "Password protected ZIP"))
        if ext.endswith(".rar"): results.append(("RAR", "Password protected RAR"))
        if ext.endswith(".7z"): results.append(("7Z", "Password protected 7z"))
        if ext.endswith(".pdf"): results.append(("PDF", "Password protected PDF"))
        if ext.endswith((".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx")):
            results.append(("OFFICE", "Password protected Office"))
        if ext.endswith(".kdbx"): results.append(("KEEPASS", "KeePass database"))
        if ext.endswith(".pcapng") or ext.endswith(".cap"):
            results.append(("WPA", "WiFi WPA/WPA2 Handshake"))
        if ext.endswith(".gpg") or ext.endswith(".pgp"):
            results.append(("GPG", "Encrypted GPG/PGP file"))
        if ext.endswith(".btc") or ext.endswith(".wallet"):
            results.append(("BTC", "Bitcoin wallet"))
        if ext.endswith(".eth"):
            results.append(("ETH", "Ethereum wallet"))
        if ext.endswith(".zipx"):
            results.append(("ZIPX", "Extended ZipX archive"))
        if ext.endswith(".keychain"):
            results.append(("KEYCHAIN", "macOS Keychain database"))
        if ext.endswith(".sqlcipher"):
            results.append(("SQLCIPHER", "SQLCipher Encrypted Database"))
        if ext.endswith(".apk"):
            results.append(("APK", "Android APK (keystore detection needed)"))

        # Scan isi file untuk hash
        with open(filepath, "rb") as f:
            content = f.read()
            try:
                text = content.decode(errors="ignore")
                words = text.split()
                for w in words:
                    htype = detect_hash_type(w.lower())
                    if htype:
                        results.append((htype, w.lower()))
            except:
                pass
    except Exception as e:
        print(f"[!] Error scanning file: {e}")
    return results

def crack_with_hashcat(hash_value, hash_type):
    hash_modes = {
        "MD5":"0","SHA1":"100","SHA224":"1300","SHA256":"1400","SHA384":"10800","SHA512":"1700",
        "LM":"3000","NTLM":"1000"
    }
    if hash_type not in hash_modes:
        return None
    with open("hash.txt","w") as f: f.write(hash_value+"\n")
    subprocess.run([
        "hashcat","-a","0","-m",hash_modes[hash_type],
        "hash.txt","/usr/share/wordlists/rockyou.txt","--force","--quiet"
    ])
    result=subprocess.check_output(["hashcat","-m",hash_modes[hash_type],"--show","hash.txt"]).decode()
    return result.strip()

def crack_with_john(hash_value, hash_type):
    with open("hash.txt","w") as f: f.write("user:"+hash_value+"\n")
    subprocess.run([
        "john","--format=raw-"+hash_type.lower(),
        "--wordlist=/usr/share/wordlists/rockyou.txt","hash.txt"
    ])
    result=subprocess.check_output(["john","--show","hash.txt"]).decode()
    return result.strip()

def crack_zip(filepath):
    try:
        result=subprocess.check_output([
            "fcrackzip","-u","-D","-p","/usr/share/wordlists/rockyou.txt",filepath
        ]).decode()
        return result.strip()
    except: return None

def crack_rar(filepath):
    try:
        result=subprocess.check_output([
            "rarcrack",filepath,"--type","rar","--threads","4","--wordlist","/usr/share/wordlists/rockyou.txt"
        ]).decode()
        return result.strip()
    except: return None

def crack_7z(filepath):
    try:
        subprocess.run(["7z2john.pl",filepath],stdout=open("7z.hash","w"))
        subprocess.run(["john","--wordlist=/usr/share/wordlists/rockyou.txt","7z.hash"])
        result=subprocess.check_output(["john","--show","7z.hash"]).decode()
        return result.strip()
    except: return None

def crack_pdf(filepath):
    try:
        result=subprocess.check_output([
            "pdfcrack","-f",filepath,"-w","/usr/share/wordlists/rockyou.txt"
        ]).decode()
        return result.strip()
    except: return None

def crack_office(filepath):
    try:
        with open("office.hash","w") as f:
            subprocess.run(["office2john.py",filepath],stdout=f)
        subprocess.run(["john","--wordlist=/usr/share/wordlists/rockyou.txt","office.hash"])
        result=subprocess.check_output(["john","--show","office.hash"]).decode()
        return result.strip()
    except: return None

def crack_keepass(filepath):
    try:
        with open("kp.hash","w") as f:
            subprocess.run(["keepass2john",filepath],stdout=f)
        subprocess.run(["john","--wordlist=/usr/share/wordlists/rockyou.txt","kp.hash"])
        result=subprocess.check_output(["john","--show","kp.hash"]).decode()
        return result.strip()
    except: return None

def crack_wpa(filepath):
    try:
        subprocess.run(["hcxpcapngtool","-o","wpa.hccapx",filepath])
        subprocess.run([
            "hashcat","-m","2500","wpa.hccapx","/usr/share/wordlists/rockyou.txt","--force","--quiet"
        ])
        result=subprocess.check_output(["hashcat","-m","2500","--show","wpa.hccapx"]).decode()
        return result.strip()
    except: return None

def crack_gpg(filepath):
    try:
        result=subprocess.check_output([
            "gpg2john",filepath
        ]).decode()
        with open("gpg.hash","w") as f: f.write(result)
        subprocess.run(["john","--wordlist=/usr/share/wordlists/rockyou.txt","gpg.hash"])
        result=subprocess.check_output(["john","--show","gpg.hash"]).decode()
        return result.strip()
    except: return None

def crack_btc(filepath):
    try:
        result=subprocess.check_output([
            "btc2john.py",filepath
        ]).decode()
        with open("btc.hash","w") as f: f.write(result)
        subprocess.run(["john","--wordlist=/usr/share/wordlists/rockyou.txt","btc.hash"])
        result=subprocess.check_output(["john","--show","btc.hash"]).decode()
        return result.strip()
    except: return None

def crack_eth(filepath):
    try:
        result=subprocess.check_output([
            "ethereum2john.py",filepath
        ]).decode()
        with open("eth.hash","w") as f: f.write(result)
        subprocess.run(["john","--wordlist=/usr/share/wordlists/rockyou.txt","eth.hash"])
        result=subprocess.check_output(["john","--show","eth.hash"]).decode()
        return result.strip()
    except: return None

def crack_keychain(filepath):
    try:
        result=subprocess.check_output([
            "keychain2john",filepath
        ]).decode()
        with open("kc.hash","w") as f: f.write(result)
        subprocess.run(["john","--wordlist=/usr/share/wordlists/rockyou.txt","kc.hash"])
        result=subprocess.check_output(["john","--show","kc.hash"]).decode()
        return result.strip()
    except: return None

def crack_sqlcipher(filepath):
    try:
        result=subprocess.check_output([
            "sqlcipher2john.py",filepath
        ]).decode()
        with open("sql.hash","w") as f: f.write(result)
        subprocess.run(["john","--wordlist=/usr/share/wordlists/rockyou.txt","sql.hash"])
        result=subprocess.check_output(["john","--show","sql.hash"]).decode()
        return result.strip()
    except: return None

def main():
    filepath=input("Masukkan lokasi file: ").strip()
    if not os.path.isfile(filepath):
        print("File tidak ditemukan."); sys.exit(1)

    print("[*] Memindai file...")
    results=scan_file(filepath)
    if not results:
        print("Tidak ada enkripsi yang terdeteksi."); sys.exit(0)

    print("\n[+] Ditemukan kemungkinan enkripsi:")
    for i,r in enumerate(results,1): print(f"{i}. {r[0]} -> {r[1]}")

    choice=input("Pilih nomor untuk mencoba membuka: ").strip()
    if not choice.isdigit(): print("Pilihan tidak valid."); sys.exit(1)
    choice=int(choice)
    if choice<1 or choice>len(results): print("Pilihan tidak valid."); sys.exit(1)

    sel=results[choice-1]; hasil=None
    if sel[0] in ["MD5","SHA1","SHA224","SHA256","SHA384","SHA512","LM","NTLM"]:
        hasil=crack_with_hashcat(sel[1],sel[0])
    elif sel[0]=="ZIP": hasil=crack_zip(filepath)
    elif sel[0]=="RAR": hasil=crack_rar(filepath)
    elif sel[0]=="7Z": hasil=crack_7z(filepath)
    elif sel[0]=="PDF": hasil=crack_pdf(filepath)
    elif sel[0]=="OFFICE": hasil=crack_office(filepath)
    elif sel[0]=="KEEPASS": hasil=crack_keepass(filepath)
    elif sel[0]=="WPA": hasil=crack_wpa(filepath)
    elif sel[0]=="GPG": hasil=crack_gpg(filepath)
    elif sel[0]=="BTC": hasil=crack_btc(filepath)
    elif sel[0]=="ETH": hasil=crack_eth(filepath)
    elif sel[0]=="KEYCHAIN": hasil=crack_keychain(filepath)
    elif sel[0]=="SQLCIPHER": hasil=crack_sqlcipher(filepath)
    else: hasil=crack_with_john(sel[1],sel[0])

    if hasil: print(f'\n[+] Hasilnya adalah "{hasil}"')
    else: print("[!] Tidak berhasil menemukan hasil.")

if __name__=="__main__": main()
