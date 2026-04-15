#!/usr/bin/env python3
"""Install Python dependencies from requirements.txt."""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REQ = HERE / "requirements.txt"


def ask(question: str, options: list[str]) -> str:
    print(f"\n{question}")
    for i, opt in enumerate(options, 1):
        print(f"  {i}) {opt}")
    while True:
        choice = input(f"[1-{len(options)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        print("Invalid choice.")


def main() -> int:
    if not REQ.exists():
        print(f"No requirements.txt found in {HERE}")
        return 1

    print(f"=== Install dependencies for {HERE.name} ===")
    print(f"requirements.txt: {REQ}")

    with open(REQ) as f:
        deps = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not deps:
        print("No dependencies found.")
        return 0

    print(f"\nPackages: {', '.join(deps)}")

    method = ask("How to install?", [
        "pip install (user)",
        "pip install --break-system-packages",
        "venv (create virtualenv here)",
        "dnf install (system packages)",
    ])

    if method.startswith("pip install (user)"):
        cmd = [sys.executable, "-m", "pip", "install", "--user", "-r", str(REQ)]
    elif method.startswith("pip install --break"):
        cmd = [sys.executable, "-m", "pip", "install", "--break-system-packages", "-r", str(REQ)]
    elif method.startswith("venv"):
        venv_dir = HERE / "venv"
        print(f"\nCreating venv in {venv_dir} ...")
        subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
        pip = venv_dir / "bin" / "pip"
        cmd = [str(pip), "install", "-r", str(REQ)]
        print(f"Activate with: source {venv_dir}/bin/activate")
    elif method.startswith("dnf"):
        # Map pip packages to dnf names (best-effort: python3-<name>)
        dnf_pkgs = [f"python3-{d.split('>=')[0].split('[')[0].strip().lower()}" for d in deps]
        print(f"\nAttempting: sudo dnf install {' '.join(dnf_pkgs)}")
        print("Note: not all packages may be available via dnf.")
        cmd = ["sudo", "dnf", "install", "-y"] + dnf_pkgs
    else:
        return 1

    print(f"\n$ {' '.join(cmd)}\n")
    return subprocess.run(cmd).returncode


if __name__ == "__main__":
    raise SystemExit(main())
