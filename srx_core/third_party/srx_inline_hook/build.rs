use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let include_dir = manifest_dir.join("include");
    let header = include_dir.join("srx_inline_hook.h");
    println!("cargo:rerun-if-changed={}", header.display());
    println!("cargo:include={}", include_dir.display());
    verify_header_version(&header);

    let target = env::var("TARGET").expect("TARGET");
    if target != "x86_64-linux-android" && target != "aarch64-linux-android" {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let exports = export_symbols(&header);

    let exports_path = out_dir.join("srx_inline_hook.exports.txt");
    fs::write(&exports_path, exports.join("\n") + "\n").expect("write exports list");

    let version_script = out_dir.join("srx_inline_hook.version.map");
    fs::write(&version_script, version_script_text()).expect("write version script");
    let version_script_arg = version_script
        .to_str()
        .expect("version script utf8")
        .replace('\\', "/");
    println!(
        "cargo:rustc-link-arg=-Wl,--version-script={}",
        version_script_arg
    );

    for sym in &exports {
        println!("cargo:rustc-link-arg=-Wl,-u,{}", sym);
    }

    if env::var_os("SRX_SKIP_EXPORT_CHECK").is_none() {
        verify_previous_build_exports(&manifest_dir, &target, &exports);
    }
}

fn verify_header_version(header: &PathBuf) {
    let text = fs::read_to_string(header).expect("read public header");
    let expected = format!(
        "#define SRX_INLINE_HOOK_VERSION \"{}\"",
        env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION")
    );
    assert!(
        text.contains(&expected),
        "public header version must match Cargo package version"
    );
}

fn export_symbols(header: &PathBuf) -> Vec<String> {
    let text = fs::read_to_string(header).expect("read public header");
    let mut filtered = String::with_capacity(text.len());
    let mut skipping_preprocessor = false;

    for line in text.lines() {
        if skipping_preprocessor {
            skipping_preprocessor = line.trim_end().ends_with('\\');
            continue;
        }
        if line.trim_start().starts_with('#') {
            skipping_preprocessor = line.trim_end().ends_with('\\');
            continue;
        }
        filtered.push_str(line);
        filtered.push('\n');
    }

    let bytes = filtered.as_bytes();
    let mut exports = BTreeSet::new();
    let mut i = 0usize;

    while let Some(found) = filtered[i..].find("srx_inline_hook_") {
        let start = i + found;
        let mut end = start;
        while end < bytes.len() {
            let b = bytes[end];
            if b.is_ascii_alphanumeric() || b == b'_' {
                end += 1;
            } else {
                break;
            }
        }
        if end > start {
            let mut next = end;
            while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                next += 1;
            }
            if next < bytes.len() && bytes[next] == b'(' {
                exports.insert(filtered[start..end].to_owned());
            }
        }
        i = end.max(start + 1);
    }

    exports.into_iter().collect()
}

fn version_script_text() -> &'static str {
    // Rust 自动导出表的精确规则优先；通配规则为汇编入口补充版本，不重复分配。
    "SRX_INLINE_HOOK {\n  global:\n    srx_inline_hook_*;\n  local:\n    *;\n};\n"
}

fn verify_previous_build_exports(manifest_dir: &Path, target: &str, exports: &[String]) {
    let lib_path = manifest_dir
        .join("target")
        .join(target)
        .join("release")
        .join("libsrx_inline_hook.so");
    if !lib_path.exists() {
        return;
    }

    let Some(llvm_readelf) = find_llvm_readelf() else {
        return;
    };
    let output = Command::new(&llvm_readelf)
        .arg("--dyn-syms")
        .arg(&lib_path)
        .output()
        .expect("run llvm-readelf for export check");
    if !output.status.success() {
        panic!(
            "llvm-readelf export check failed for {}: {}",
            lib_path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let exported = parse_exported_symbols(&stdout);
    if exported.is_empty() {
        return;
    }
    let expected: BTreeSet<String> = exports.iter().cloned().collect();
    let missing: Vec<String> = expected.difference(&exported).cloned().collect();
    if !missing.is_empty() {
        panic!(
            "public ABI export check failed for {}: missing {:?}",
            lib_path.display(),
            missing
        );
    }

    let extra: Vec<String> = exported.difference(&expected).cloned().collect();
    if !extra.is_empty() {
        panic!(
            "public ABI export check failed for {}: unexpected {:?}",
            lib_path.display(),
            extra
        );
    }
}

fn find_llvm_readelf() -> Option<PathBuf> {
    let ndk_home = find_ndk_home()?;
    let tool = ndk_home
        .join("toolchains")
        .join("llvm")
        .join("prebuilt")
        .join(ndk_prebuilt_tag())
        .join(if cfg!(windows) {
            "bin/llvm-readelf.exe"
        } else {
            "bin/llvm-readelf"
        });
    tool.exists().then_some(tool)
}

fn find_ndk_home() -> Option<PathBuf> {
    ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_HOME"]
        .into_iter()
        .filter_map(|key| env::var(key).ok())
        .map(PathBuf::from)
        .find(|path| path.exists())
        .or_else(find_ndk_from_android_sdk)
}

fn find_ndk_from_android_sdk() -> Option<PathBuf> {
    let sdk = ["ANDROID_HOME", "ANDROID_SDK_ROOT"]
        .into_iter()
        .filter_map(|key| env::var(key).ok())
        .map(PathBuf::from)
        .find(|path| path.exists())?;
    fs::read_dir(sdk.join("ndk"))
        .ok()?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .max_by(|a, b| a.file_name().cmp(&b.file_name()))
}

fn ndk_prebuilt_tag() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows-x86_64"
    } else if cfg!(target_os = "macos") {
        "darwin-x86_64"
    } else {
        "linux-x86_64"
    }
}

fn parse_exported_symbols(text: &str) -> BTreeSet<String> {
    let mut exported = BTreeSet::new();
    for line in text.lines() {
        let Some(name) = line.split_whitespace().last() else {
            continue;
        };
        let Some(sym) = name.split("@@").next() else {
            continue;
        };
        if sym.starts_with("srx_inline_hook_") {
            exported.insert(sym.to_owned());
        }
    }
    exported
}
