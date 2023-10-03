# threadless_loader_rs

## Descriptions
threadless_loader_rs is a payload creation tool used for circumventing EDR security controls based around CCob's [ThreadlessInject POC](https://github.com/CCob/ThreadlessInject/). There are some improvments to the original POC inlcuding executing the shellcode in a new thread. This allows for example a C2 beacon to be injected and the beacon will execute under the context of a new thread. Additionally, I added support for remote module enumeration so you can specify any DLL and export function to hijack not just Known DLLs.

## Usage
Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals, it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	C:\Users\User\Desktop\threadless_loader_rs> set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"
 
~~~
Usage: threadless_loader_rs.exe [OPTIONS] --process <PROCESS> --dll <DLL> --export <EXPORT> --output <OUTPUT>

Options:
  -p, --process <PROCESS>                Process to inject into
  -s, --shellcode-file <SHELLCODE_FILE>  Path for x64 shellcode
  -d, --dll <DLL>                        DLL that contains the export to patch
  -e, --export <EXPORT>                  Exported function that will be hijacked
  -o, --output <OUTPUT>                  Name of output file (e.g. loader.exe or loader.dll)
  -f, --function <FUNCTION>              Name of the output dlls export function
  -h, --help                             Print help
  -V, --version                          Print version
~~~

## Supported Payloads

Right now can generate either a `.exe` or `.dll` file. To specify this, ensure that the `--output` option ends with either a `.exe` for binaries or `.dll` for dlls.

## Kudos

- @CCoB for the original [POC](https://github.com/CCob/ThreadlessInject/) and reaserch 
- @Kudaes for [DInvoke project](https://github.com/Kudaes/DInvoke_rs) which is used heavily in this project to make windows API calls
- @Tylous for his work on [Freeze.rs](https://github.com/Tylous/Freeze.rs). I used alot of the rust "meta programming" code for creating the payloads.
- @mr-nukealizer for their [implementation](https://www.codeproject.com/Tips/139349/Getting-the-address-of-a-function-in-a-DLL-loaded) of remote module enumeration
- @Cracked5pider for their [ShellcodeTemplate](https://github.com/Cracked5pider/ShellcodeTemplate) project

## To-Do

- [ ] Add option for sandbox evasion
- [ ] Add option for different encryption types
- [ ] Add option for creating process
- [ ] Add option for ETW Patching
- [ ] Add option for standalone loader
