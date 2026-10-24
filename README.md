# Kernel64Patcher
An ARM64 and ARMv7k kernel patcher based on xerub's patchfinder64, for iOS 10-18, tvOS 10-26, and watchOS 1-8.

## Compiling
```
gcc Kernel64Patcher.c -o Kernel64Patcher
```
## Usage:
Use a decompressed Mach-O kernelcache:
```
./Kernel64Patcher kcache.raw kcache.patched -a
```
Flags can be combined:

- `-a`: Patch AMFI.
- `-f`: Bypass AppleFirmwareUpdate IMG4 signature validation.
- `-s`: Bypass the SPU firmware-validation failure guard (iOS 15+).
- `-p`: Bypass the AMFI local-signing-key acquisition panic (iOS 15+).
- `-r`: Bypass the rootvp authentication panic (iOS 15+).
- `-o`: Bypass personalized root-hash authentication (iOS 15+).
- `--dry-run`: Report changes without writing output.

A flag whose target check is absent reports that it is not applicable.

## Credits/Thanks
* xerub for patchfinder64
* iH8sn0w for code
