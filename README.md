Project was implemented in C language with the use of pcap library.
Sniffer does not support ipv6. 
Extensive documentation can be found in IPK2.pdf file.

## Running project

sudo get-apt install libpcap-dev.

Priklady spustenia sudo ./sniffer -i enp0s3 --n 10 --p 53
                        ./sniffer -i enp0s3 --n 10 --p 22
                        ./sniffer -i enp0s3 --n 10 --p 22
## Project Structure
```                       
.
├── CMakeLists.txt
├── FindPCAP.cmake
├── IPK2.pdf
├── Makefile
├── README.md
└── src
    └── main.c

```

  - **CMakeLists.txt** - generated via Clion, and is hardcoded for the reference virtual machine that for this project
  - **FindPCAP.cmake** - generated via Clion, and is hardcoded aswell
  - **IPK2.pdf** - documentation of the project
  - **Makefile** - makefile with sets of rules used to run and compile the project from the CLI
  - **README.md** - readme
  - **main.c** - actual code of the project
