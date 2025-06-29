# HOW TO USE    
  
(1.7.0 BETA)  
  
````markdown
# HCA for Linux  
  
A fast and intelligent folder archiver using LZMA or Zstandard, with deduplication and optional password support.  
  
---  
  
### 1. **Ensure Python is Installed**  
  
Most Linux distros already include Python. Check with:  
  
```bash  
python3 --version  
````  
  
If needed:  
  
```bash  
sudo apt update  
sudo apt install python3 python3-pip  
```
  
---  
  
### 2. **Install HCA with the Installer**               
                   
Just run the installer script:                 
                               
```bash                
sudo python3 install.py            
```           
                      
Then apply the PATH change (if not applied automatically):                
               
```bash                 
source ~/.bashrc  
```                 

✅ After that, you can run `hca` globally from anywhere:             
               
```bash                
hca --version  
```              
               
---                             
                     
### 3. **Manual Setup (Advanced Users)**                                                   
                   
If you prefer not to use the installer, you can run `HCA.py` manually.            
                       
#### a) Install required dependencies         
                
HCA requires:                  
                     
* `zstandard` (preferred, optional)               
* `lzma` (built-in to Python 3)               
                                      
To install Zstandard:                                     
                      
```bash                                    
pip3 install zstandard                 
```                              
                 
#### b) Save the script             
               
Save `HCA.py` in any folder.                   
                        
#### c) Make it executable (optional)                                          
                
```bash                   
chmod +x HCA.py               
```                               
               
Run it with:             
                    
```bash                    
python3 HCA.py [options]                   
```                  
                            
---    
                
### 4. **Usage Examples**                     
                 
#### 🗜 Compress a folder                      
                  
```bash                             
hca --compress myfolder --output backup.hca --password --delete                
```                             
                 
#### 📦 Extract an archive                   
                                        
```bash
hca --extract backup.hca --output extracted_folder --password                
```
               
#### 📃 List archive contents               
                 
```bash               
hca --list backup.hca                  
```                
               
#### 📖 Show manual                                                                
            
```bash            
hca --man            
```            
                      
---              
               
### 5. **Notes on Flags**                     
                     
* `--password`: prompts for password (not enforced yet)           
* `--delete`: deletes input folder after confirmation             
* `--split`: reserved for future split-archive support                  
              
---                               
                                                        
### 6. **(Optional) Create a Manual Alias**                                          
                 
If not using the installer, you can add this to `~/.bashrc`:          
                 
```bash                                     
alias hca='python3 /full/path/to/HCA.py'                
```              
                           
Then reload:                                         
                        
```bash           
source ~/.bashrc               
```                                  
                 
Now use `hca` globally.                
            
---            
                
### ✅ That's it!                                    
                           
Need help? Use:                  
                     
```bash         
hca --tldr                      
```                          
                 
or              
               
```bash             
hca --man               
```                   
