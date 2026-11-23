use std::env;
use std::fs;
use std::path::PathBuf;

// 向依赖方（srx_core 的 C++ 桥接）暴露头文件目录，并校验头文件版本与包版本一致
fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let include_dir = manifest_dir.join("include");
    let header = include_dir.join("srx_inline_hook.h");
    println!("cargo:rerun-if-changed={}", header.display());
    println!("cargo:include={}", include_dir.display());

    let text = fs::read_to_string(&header).expect("read public header");
    let expected = format!(
        "#define SRX_INLINE_HOOK_VERSION \"{}\"",
        env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION")
    );
    assert!(
        text.contains(&expected),
        "public header version must match Cargo package version"
    );
}
