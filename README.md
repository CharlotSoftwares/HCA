# HCA - Highly Compressed Archive Utility  
  
Version: 0.6.0  
  
---  
  
## Overview  
  
HCA is a command-line utility to compress and extract folders/files into a highly compressed archive format (`.hca`).    
It supports multi-threaded compression, AES-256 encryption with password, split archives, deletion of original files after compression (with confirmations), and detailed metadata.  
  
---  
  
## Features  
  
- Compress entire folders with multi-threading for speed.  
- Extract archives with integrity checks.  
- List contents and metadata of archives.  
- AES-256 password encryption/decryption.  
- Split archives into 50MB parts for easier handling.  
- Confirmed deletion of original files after successful compression.  
- Safe filename enforcement.  
- Detailed progress and messages.  
- Manual (`--man`), help (`--help`), and summary (`--tldr`) commands.  
- Version information display.  
- Error codes for scripting.  
  
---  
  
## Requirements  
  
- Python 3.7+  
- `pycryptodome` library (`pip install pycryptodome`)  
  
---  
  
## Usage  
  
Run from command line:  
  
```bash   
python hca.py [options]  
````  
  
### Options  
  
| Flag                          | Description                                                                                          |        
| ----------------------------- | ---------------------------------------------------------------------------------------------------- |            
| `--compress`                  | Compress the given folder/files                                                                      |               
| `--extract`                   | Extract the given archive                                                                            |           
| `--list`                      | List contents and metadata of an archive                                                             |              
| `--output` (`-o`)             | Specify the output file or folder                                                                    |             
| `--password`                  | Enable AES-256 encryption/decryption with a password prompt                                          |               
| `--delete`                    | Delete input files after successful compression (asks twice for confirmation)                        |               
| `--split`                     | Split archive into multiple parts (\~50MB each)                                                      |             
| `--ultra`                     | Use ultra compression mode (higher compression, slower)                                              |              
| `--ultra-plus`                | Use ultra-plus compression mode (maximum compression, slowest, best ratio, compress compressed data) |  
| `--version`                   | Show the version of the program                                                                      |  
| `--help` / `--man` / `--tldr` | Show help, manual, or summary information                                                            |  
  
    
---    
  
## Examples  
  
Compress a folder with password, split archive, and delete original files:  

```bash  
python hca.py --compress myfolder --output backup.hca --password --split --delete  
```  
  
Extract an encrypted archive:  
  
```bash  
python hca.py --extract backup.hca --output extracted_folder --password  
```  
  
List archive contents:  
    
```bash  
python hca.py --list backup.hca  
```  

Show version:  
  
```bash  
python hca.py --version  
```  
  
Show manual/help:  
  
```bash  
python hca.py --help  
```  
  
---  
  
## Notes  
  
* Only filenames with letters, digits, dash, underscore, dot, and spaces are supported for safety.  
* Password encryption uses AES-256-CBC.  
* Splitting creates multiple files named like `backup.hca.part1`, `backup.hca.part2`, etc.  
* During deletion, the tool asks twice before removing each file.  
* Metadata includes creator user, creation timestamp, file count, and archive version.  
* Multi-threading uses up to 4 threads for compression workers.  
  
---  
  
## Building Windows Executable (.exe)  
  
To build a standalone Windows executable using PyInstaller:  
  
1. Install PyInstaller:  
  
```bash  
pip install pyinstaller  
```  
  
2. Run:  
  
```bash  
pyinstaller --onefile hca.py  
```  
  
3. The executable will be in the `dist` folder as `hca.exe`.  
  
---  
  
## License  
  
MIT License — free to use and modify.  
  
---  
  
## Contact & Contributions  
  
For bugs or feature requests, please open an issue or contact the author.  
  
---  
  
Thank you for using HCA!  
  
# [INSTRUCTIONS FOR LINUX](https://GitHub.com/CharlotOS/HCA/blob/main/LinuxREADME.md)
  
