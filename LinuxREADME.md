
### 1. **Make sure you have Python installed**  
  
Most Linux distros come with Python pre-installed. Check your version:  
  
```bash  
python3 --version  
```  
  
If it’s missing or too old, install Python 3 (usually):  
*(Debian-based example)*  
  
```bash  
sudo apt update  
sudo apt install python3 python3-pip  
```  
  
---  
  
### 2. **Install required dependencies**  
  
The app uses the `pycryptodome` library. Install it with pip:  
  
```bash  
pip3 install pycryptodome  
```  
  
---  
  
### 3. **Save the script**  
  
* Save the HCA Python script as `hca.py` in a folder you want.  
  
---  
  
### 4. **Make the script executable (optional)**  
  
```bash  
chmod +x hca.py  
```  
  
You can now run it directly with `./hca.py`.  
  
---  
  
### 5. **Run HCA commands**  
  
Run the script with `python3` or `./hca.py` plus the flags.  
  
**Examples:**  
  
* Compress a folder named `myfolder` into `backup.hca` with password and split:  
  
```bash  
python3 hca.py --compress myfolder --output backup.hca --password --split --delete  
```  
  
* Extract an archive to a folder:  
  
```bash  
python3 hca.py --extract backup.hca --output extracted_folder --password  
```  
  
* List archive contents:  
  
```bash  
python3 hca.py --list backup.hca  
```  
  
* Show manual:  
  
```bash  
python3 hca.py --man  
```  
  
---  
  
### 6. **Notes on usage**  
  
* If you use the `--password` flag, the app will prompt you to enter a password.  
* The `--delete` flag asks twice before deleting original files after successful compression.  
* The `--split` flag splits archives into 50MB chunks for easier storage/transfers.  
  
---  
    
### 7. **(Optional) Create an alias**  
  
To run `hca` from anywhere easily, add an alias in your `.bashrc` or `.zshrc`:  
  
```bash  
alias hca='python3 /path/to/hca.py'  
```  
  
Then reload your shell:  
  
```bash  
source ~/.bashrc  # or ~/.zshrc  
```  
  
Now you can just run:  
  
```bash  
hca --compress myfolder --output backup.hca   
```  
  
---  
