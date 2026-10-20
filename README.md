# Kernel64Patcher
An ARM64 kernel patcher based on xerub's patchfinder64, with ARMv7k support for Apple Watch Series 0-3.

## Compiling
```
gcc Kernel64Patcher.c -o Kernel64Patcher
```
## Usage:
```
./Kernel64Patcher kcache.raw kcache.patched -a
```
## Credits/Thanks
* xerub for patchfinder64
* iH8sn0w for code

Supported Watch kernels, by exact device and build:

| Device | watchOS | Build |
| --- | --- | --- |
| Watch1,1 | 1.0.1 / 2.2.2 / 3.2.3 / 4.3.2 | 12S632 / 13V604 / 14V753 / 15U70 |
| Watch1,2 | 1.0.1 / 2.2.2 / 3.2.3 / 4.3.2 | 12S632 / 13V604 / 14V753 / 15U70 |
| Watch2,3 | 3.2.3 / 4.3.2 / 5.3.10 / 6.3.1 | 14V753 / 15U70 / 16U711 / 17U224 |
| Watch2,4 | 3.2.3 / 4.3.2 / 5.3.10 / 6.3.1 | 14V753 / 15U70 / 16U711 / 17U224 |
| Watch2,6 | 3.2.3 / 4.3.2 / 5.3.10 / 6.3.1 | 14V753 / 15U70 / 16U711 / 17U224 |
| Watch2,7 | 3.2.3 / 4.3.2 / 5.3.10 / 6.3.1 | 14V753 / 15U70 / 16U711 / 17U224 |
| Watch3,1 | 4.3.2 / 5.3.10 / 6.3.1 / 7.6.2 / 8.8.2 | 15U70 / 16U711 / 17U224 / 18U80 / 19U526 |
| Watch3,2 | 4.3.2 / 5.3.10 / 6.3.1 / 7.6.2 / 8.8.2 | 15U70 / 16U711 / 17U224 / 18U80 / 19U526 |
| Watch3,3 | 4.3.2 / 5.3.10 / 6.3.1 / 7.6.2 / 8.8.2 | 15U70 / 16U711 / 17U224 / 18U80 / 19U526 |
| Watch3,4 | 4.3.2 / 5.3.10 / 6.3.1 / 7.6.2 / 8.8.2 | 15U70 / 16U711 / 17U224 / 18U80 / 19U526 |
