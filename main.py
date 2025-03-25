import os
import sys
import subprocess

def check_pyinstaller(binary_path):
    """Check if the binary is a PyInstaller package"""
    with open(binary_path, "rb") as f:
        data = f.read(1024)
    return b"pyi-runtime" in data or b"pyi-magic" in data

def extract_pyinstaller(binary_path, output_folder):
    """Extract PyInstaller ELF binaries"""
    print(f"[+] PyInstaller binary detected. Extracting to: {output_folder}")
    os.system(f"python pyinstxtractor.py {binary_path}")
    print("[+] Extraction complete. Check the extracted folder.")

def decompile_elf(binary_path, output_folder):
    """Decompile ELF binary"""
    asm_file = os.path.join(output_folder, "decompiled.asm")
    strings_file = os.path.join(output_folder, "strings.txt")

    print(f"[+] Running objdump... (Saving to {asm_file})")
    os.system(f"objdump -d {binary_path} > {asm_file}")

    print(f"[+] Extracting strings... (Saving to {strings_file})")
    os.system(f"strings {binary_path} > {strings_file}")

    print("[+] Decompilation completed! Check output folder.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python auto_elf_decompiler.py <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]

    if not os.path.exists(binary_path):
        print("[-] File not found!")
        sys.exit(1)

    output_folder = f"{binary_path}_decompiled"
    os.makedirs(output_folder, exist_ok=True)

    if check_pyinstaller(binary_path):
        extract_pyinstaller(binary_path, output_folder)
    else:
        decompile_elf(binary_path, output_folder)

if __name__ == "__main__":
    main()
