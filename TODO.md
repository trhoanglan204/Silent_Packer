
# Packer
- [x] Make README file
- [ ] Add dynamic library support
- [x] Add PIE support
- [ ] Add new ciphers
    - [x] AES
# Obfuscate 
- [ ] Using header obfuscate.h to reduce debug string on final file
## ELF
- [ ] Need review arm32 (tested on qemu 8+), not waranteed to 100% work (but at least 80%)
> I'm not sure the bug, may be more than 5+ type chip arm32
- [ ] Currently not applied silvio_infection (I just release the highest and stable version)
## PE
- [+] Add Overlay
### 32 bit
- [ ] Need to test it
### 64 bit
- [+] Tested with "Process Explorer" and it worked
### Code cave
- [ ] Need review, worked mostly (90% cases passed)

### Section insertion
- [x] Until now still good

### Overlay
- [ ] Need to fake signature as well
- [+] Fake checksum 

## AES
- [x] Add AES-128-ECB support for PE32, PE32+, ELF32
- [ ] Add AES-128-ECB support for ARMv7, Aarch64, MIPS32, MIPS64

