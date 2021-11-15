Projekt bol implementovany pomocou jazyka C a kniznice pcap.h. 
Pre spravnu funkcost programu je tato kniznica potrebna. 
Instaluje sa pomocou sudo get-apt install libpcap-dev.
Sniffer bol implementovany na MacOS Catalina a nasledne otestovany na referencom stroji
pre sietove predmety na FIT VUT PDS VM.

Sniffer nepodporuje ipv6. 

Priklady spustenia sudo ./sniffer -i enp0s3 --n 10 --p 53
                        ./sniffer -i enp0s3 --n 10 --p 22
                        ./sniffer -i enp0s3 --n 10 --p 22
                        
