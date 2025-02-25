# AlcatrazLdr

*An evasive shellcode loader with indirect syscalls, thread name-calling allocation, and PoolParty injection.*

```
                                -- 
                               /--\                                                                 
                              /----\                                                                
                             |      |                                                               
                             |      |                                                               
                             |      |                                                               
                             |      |                                                               
                             |      |                                                               
                             |      |                                                               
                             |      |                                                               
                             |      |----------------------------------------------                 
                             |      /                                              \       #        
                             |     /                                                \    *#""       
                             |    /                                                  \     ##"      
                             |   |----------------------------------------------------|      #"     
                             |   |                                                    |       #"    
                             |   |  [||]   [||]   [||]   [||]   [||]   [||]   [||]    |       **"   
                             |   |                                                    |             
                             |   |  [||]   [||]   [||]   [||]   [||]   [||]   [||]    |   < EVADE! >
                             |   |   _____ _         _               __      _        |  /          
                         @   |   |  |  _  | |___ ___| |_ ___ ___ ___|  |   _| |___    | --    @@$   
                        @    ++++|  |     | |  _| .'|  _|  _| .'|- _|  |__| . |  _|   |╹_╹ )  @     
                        @       +|  |__|__|_|___|__,|_| |_| |__,|___|_____|___|_|     |⊂ﾉ    @@     
                        @        |                                                    |     @@      
                        @@       ------------------------------------------------------   @@        
                         @@                                                             @@@         
                          @@                                                          @@@           
                           @@                                                     @@@@              
                             @@                                            @ @@@@@                  
                               @@@@       @@ @@@@@@@@@@@@    @@   @@@@@@@@@                         
                                  @@@@@@@@@@@@@@      @@@@@@@@@@@@@
```

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Notes](#notes)

---

## Features

- **AV/EDR Evasion:** Utilizes shellcode encoding and indirect syscalls through the *Hell's Gate* technique.
- **Remote Process Injection:** Inject shellcode into remote processes via the *Thread name-calling* method.
- **Shellcode Execution:** Executes shellcode via the *PoolParty* technique (*Direct I/O*).

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/aniko33/AlcatrazLdr.git
   cd AlcatrazLdr
   ```

2. Run the AlcatrazLdr builder (ensure Python 3 is installed):
   ```bash
   python alcatrazLdr.py --help
   ```

---

## Usage

```
usage: AlcatrazLdr [-h] [--quiet] [--debug] [--docker] file

Evasive shellcode loader with indirect syscalls, Thread name-calling allocation, PoolParty injection

positional arguments:
  file           File to embed into the loader

options:
  -h, --help     show this help message and exit
  --quiet, -q    No banner
  --debug, -d    Debug flag
  --docker, -dk  Docker flag
```

To create a new executable:
```bash
python alcatrazLdr.py <path_to_shellcode.bin>
```

To create a new executable with Docker support:
```bash
python alcatrazLdr.py <path_to_shellcode.bin> --docker
```

To create a new executable with the debug flag enabled:
```bash
python alcatrazLdr.py <path_to_shellcode.bin> --debug
```

To suppress the banner output:
```bash
python alcatrazLdr.py <path_to_shellcode.bin> --quiet
```

---

## Notes

- The shellcode size is limited to **65532 bytes** due to the `RtlInitUnicodeStringEx` function.
