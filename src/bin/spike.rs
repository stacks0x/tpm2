//! Step 0 Option A harness (tss-esapi). Requires `--features esapi`.
//!
//! Run: `cargo run --features esapi --bin spike -- <command>`

#[cfg(target_os = "macos")]
fn main() {
    eprintln!("spike: macOS has no TPM");
    std::process::exit(1);
}

#[cfg(not(target_os = "macos"))]
fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "all".to_string());

    let result = match cmd.as_str() {
        "probe" => run_probe(),
        "pcr-read" => run_pcr_read(),
        "blob-roundtrip" => run_blob_roundtrip(),
        "quote" => run_quote(),
        "all" => {
            run_probe()?;
            run_pcr_read()?;
            run_blob_roundtrip()?;
            run_quote()?;
            println!("\nspike: all checks passed");
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}");
            eprintln!("usage: spike [probe|pcr-read|blob-roundtrip|quote|all]");
            std::process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("spike FAILED: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn run_probe() -> Result<(), String> {
    println!("== probe ==");
    let props = node_tpm2::tpm::probe()?;
    println!("  manufacturer: {}", props.manufacturer);
    println!("  firmware:     {}", props.firmware_version);
    println!("  is_virtual:   {}", props.is_virtual);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn run_pcr_read() -> Result<(), String> {
    println!("== pcr-read ==");
    let mut ctx = node_tpm2::transport::open_context()?;
    let pcrs = node_tpm2::tpm::pcr_read(&mut ctx, &[0, 1, 7])?;
    for (idx, digest) in pcrs {
        println!("  PCR {idx}: {digest}");
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn run_blob_roundtrip() -> Result<(), String> {
    println!("== blob-roundtrip ==");
    let mut ctx = node_tpm2::transport::open_context()?;
    let primary = node_tpm2::tpm::create_storage_primary(&mut ctx)?;
    let blob = node_tpm2::tpm::provision_ak_blob_under_parent(&mut ctx, primary.key_handle)?;
    println!(
        "  blob: public={} bytes, private={} bytes",
        blob.public.len(),
        blob.private.len()
    );
    let _loaded = node_tpm2::tpm::load_ak_blob(&mut ctx, primary.key_handle, &blob)?;
    println!("  load: ok (unprivileged wrapped-blob path)");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn run_quote() -> Result<(), String> {
    println!("== quote ==");
    let mut ctx = node_tpm2::transport::open_context()?;
    let primary = node_tpm2::tpm::create_storage_primary(&mut ctx)?;
    let blob = node_tpm2::tpm::provision_ak_blob_under_parent(&mut ctx, primary.key_handle)?;
    let ak = node_tpm2::tpm::load_ak_blob(&mut ctx, primary.key_handle, &blob)?;

    let qualifying = b"node-tpm2-spike-qualifying-data";
    let (message, signature) =
        node_tpm2::tpm::quote_with_ak(&mut ctx, ak, &[0, 1, 7], qualifying)?;

    println!("  quote message: {} bytes", message.len());
    println!("  quote signature: {} bytes", signature.len());
    println!("  quote: ok (unprivileged TPM2_Quote round-trip)");
    Ok(())
}
