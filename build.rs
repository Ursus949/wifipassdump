fn main() {
    println!("cargo:rerun-if-changed=.env");
    // Load .env file if present and pass WEBHOOK_URL to the compiler.
    if let Ok(contents) = std::fs::read_to_string(".env") {
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                if key.trim() == "WEBHOOK_URL" {
                    println!("cargo:rustc-env=WEBHOOK_URL={}", value.trim());
                    return;
                }
            }
        }
    }

    // If not found in .env, fall back to the shell environment.
    if let Ok(url) = std::env::var("WEBHOOK_URL") {
        println!("cargo:rustc-env=WEBHOOK_URL={url}");
    }
}
