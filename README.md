# CMPT-785-miniEFS
Except for openssl, please also make sure jsoncpp is installed before you compile the code
```bash
sudo apt install libjsoncpp-dev
```


Compile and prepare the binary:

```bash
cd /your-path-to/CMPT-785-miniEFS

g++ main.cpp -o fileserver -lcrypto -ljsoncpp

chmod +x fileserver
```



Run the fileserver binary:

```bash
./fileserver key_name
```



