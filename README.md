### How to use
* Linux
* Install PicoLisp (pil64) and monocypher (2.0.5) as shared library
* run tests.l to check all required functions 

### Alice do
* Generate pair of keys, private key protected by password (argon2i) and encrypted (Chacha20+Poly1305)
```
# pil signify-pil.l -gen mysoft
Enter password for private key, press Enter:
qwerty123
```
* Keys located in .pil directory inside $HOME
``` 
# ls -l /root/.pil/signify-pil/
total 8
-rw-r--r-- 1 root root 334 Apr 16 10:04 mysoft.prv
-rw-r--r-- 1 root root 119 Apr 16 10:04 mysoft.pub
```
* Show public key (HEX) and make it public
```
# pil signify-pil.l -showpub mysoft
12e3fc328c326b559762c526b72bb74ed1478274439411aac00f0435f84a45f9
```
* Sign file (EdDSA as Curve25519+Blake2b) and make hash (HEX) public
```
# pil signify-pil.l -sign mysoft /root/picoLisp.tgz
Enter password for private key, press Enter
qwerty123
51d860e9a3be98b01799fc322c4899502e292db6f3eb107577b1f5ab1813175e69df4cb7adc948421bb364cd630be8be23cde6a11804ac01a6fe8e0b5d0f8004
```

### Bob do
* Add public key
```
pil signify-pil.l -addpub alice 12e3fc328c326b559762c526b72bb74ed1478274439411aac00f0435f84a45f9
```
* Check file
```
# pil signify-pil.l -check alice /root/picoLisp.tgz 5860e9a3be98b01799fc322c4899502e292db6f3eb107577b1f5ab1813175e69df4cb7adc948421bb364cd630be8be23cde6a11804ac01a6fe8e0b5d0f8004
ok
```
