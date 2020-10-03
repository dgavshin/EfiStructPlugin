# Efi Graph Plugin for Ghidra 9.2 [[ru](https://github.com/shokking5/EfiGraphPlugin/blob/master/data/README_RU)]
![alt](https://github.com/shokking5/EfiGraphPlugin/blob/master/data/logo.png)

### 1. About plugin
The whole project was created to work with UEFI firmware and only for their analysis in Ghidra.

The Efi Graph Plugin was written during the [Summer of hack](https://dsec.ru/about/summerofhack/) at Digital Security, in addition to the already existing analyzer **[efiSeek] (https://github.com/DSecurity / efiSeek)**. This analyzer collects metadata about found protocols in **.efi** files of unpacked firmware and writes them to Memory Blocks of the program. Next, ** Efi Graph Plugin ** structures all metadata and composes an interactive graph of protocol connections.

![alt](https://github.com/shokking5/EfiGraphPlugin/blob/master/data/graph.png)

### 2. Protocol bindings

#### 2.1 A bit of theory
The main connection between protocols is the function in which they were used. One of the main methods for working with protocols is [Install Protocol](https://edk2-docs.gitbook.io/edk-ii-uefi-driver-writer-s-guide/5_uefi_services/51_services_that_uefi_drivers_commonly_use/513_handle_database_and_protocol-3-1-installmultipleprotocolinterfaces-and-uninstallmultipleprotocolinterfaces) and [Locate Protocol](https://edk2-docs.gitbook.io/edk-ii-uefi-driver-writer-s-guide/5_uefi_services/51_services_that_uefi_driverslip_protocol-1-3-3-locateprotocol). The first of them - **InstallProtocol** (replaced by InstallMultiplyProtocol in EKD2) - records in the Handle Database that the protocol is installed and can be used by other drivers. Only after installing the protocol, **Locate Protocol** can get its copy for further work in the driver. Accordingly, it is possible that the **EFI_A** protocol is installed (**Install Protocol**) in the **EFI_FILE_A** file, but is invoked using **LocateProtocol** in the **EFI_FILE_B** file.
#### 2.2 What is the bottom line?
The Efi Graph Plugin finds where the protocol was installed and where it was called, which function it is used by and in which part of the code it is declared. Based on this structure, the plugin creates a graph in which the user can interactively move through the entire firmware, finding the use of the protocol in different EFI files.

### 3. Installation
+ Install the new version [Ghidra 9.2](https://github.com/NationalSecurityAgency/ghidra) from sources
+ Set the environment variable `` GHIDRA_INSTALL_DIR``
+ Windows (for Linux the same steps):
``` bash
.\gradlew.bat
mv .\dist\* $Env:GHIDRA_INSTALL_DIR\Extensions\Ghidra
```
+ Open Ghidra and in the project window click ```File → Install Extensions```
+ Select ```EfiGraphPlugin``` and restart Ghidra
+ Select the prepared project ```File → Restore Project``` and select the .gar file from ./data
+ Run e5373... → Window → Struct Efi
