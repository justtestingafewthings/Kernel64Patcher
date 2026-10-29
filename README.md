# Kernel64Patcher
An ARM and ARM64 Mach-O kernel patcher for iOS, tvOS, and watchOS.

## Compiling

```sh
gcc Kernel64Patcher.c -o Kernel64Patcher
```

## Usage

Use a decompressed Mach-O kernelcache:

```sh
./Kernel64Patcher kcache.raw kcache.patched -a
```

Use `--list-patches` to list independent long options. On ARM64, `-a` selects AMFI trust, SHA-1 policy, launch constraints, and Developer Mode patches. On ARM32, it selects AMFI trust, code-signing enforcement, and library validation.

Flags can be combined:

- `-a`: Patch AMFI.
- `-f`: Bypass AppleFirmwareUpdate IMG4 signature validation.
- `-s`: Bypass the SPU firmware-validation failure guard (iOS 15+).
- `-p`: Bypass the AMFI local-signing-key acquisition panic (iOS 15+).
- `-u`: Bypass the unencrypted data-volume panic guard.
- `-r`: Bypass the rootvp authentication panic (iOS 15+).
- `-o`: Bypass personalized root-hash authentication (iOS 15+).
- `--apfs-mount-auth`: Bypass the validated APFS kernel-task mount authorization check.
- `--apfs-remount`: Bypass the validated APFS root-volume read/write remount check.
- `--fairplay-validation`: Bypass the validated legacy FairPlay executable-validation path.
- `--vm-map-protection`: Bypass the validated legacy `vm_map` maximum-protection guard.
- `--amfi-vnode-validation`: Bypass the validated legacy AMFI vnode-signature checks.
- `--legacy-cs-validation`: Bypass the validated legacy code-signature result path.
- `--nand-preserve`: Reject automatic NAND epoch/signature migration and formatting when booting SSH ramdisks on devices older than A5.
- `--dry-run`: Report changes without writing a kernel.
- `--report <path>`: Write a JSON report with patch status, file offsets, virtual addresses and original/replacement bytes.
- `--no-symbols`: Disable symbol-table assistance during discovery.

A flag whose target check is absent reports that it is not applicable. An unsupported or unresolved requested patch fails without writing a kernel. Changes are checked together for conflicts before output is written.

## Credits/Thanks

* xerub for patchfinder64
* iH8sn0w for code
* KPlooshFinder for reference AMFI patch behavior
