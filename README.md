# Efi Graph Plugin for Ghidra 9.2
![alt](https://github.com/shokking5/EfiGraphPlugin/blob/master/data/logo.png)

### 1. О плагине
Весь проект создан для работы с UEFI прошивками и только для их анализа в Ghidra. 

Efi Graph Plugin был написан во время Summer of hack в Digital Security в дополнении к уже существующему анализатору **[efiSeek](https://github.com/DSecurity/efiSeek)**. Данный анализатор собирает метаданные о найденных протоколах в **.efi** файлах распакованной прошивки и записывает их в Memory Blocks программы. Далее **Efi Graph Plugin** стуктурирует все метаданные и составляет из них интерактивный граф связей протоколов.
![alt](https://github.com/shokking5/EfiGraphPlugin/blob/master/data/graph.png)

### 2. Связи протоколов

##### 2.1 Немного теории
Основная связь между протоколами - это функция, в которой они были использованы. Одни из основных методов для работы с протоколами - это [Install Protocol](https://edk2-docs.gitbook.io/edk-ii-uefi-driver-writer-s-guide/5_uefi_services/51_services_that_uefi_drivers_commonly_use/513_handle_database_and_protocol_services#5-1-3-1-installmultipleprotocolinterfaces-and-uninstallmultipleprotocolinterfaces) и [Locate Protocol](https://edk2-docs.gitbook.io/edk-ii-uefi-driver-writer-s-guide/5_uefi_services/51_services_that_uefi_drivers_commonly_use/513_handle_database_and_protocol_services#5-1-3-3-locateprotocol). Первый из них - **InstallProtocol** (в EKD2 заменен на InstallMultiplyProtocol) - заносит в Handle Database запись о том, что протокол установлен и может использоваться другими драйверами. Только после установки протокола, **Locate Protocol** может получить его экзепляр для дальнейшей работы в драйвере. Соответственно, возможно такое, что протокол **EFI_A**  устанавливается (**Install Protocol**) в файле **EFI_FILE_A**, а вызывается с помощью **LocateProtocol** в файле **EFI_FILE_B**. 
##### 2.2 А что в итоге?
Efi Graph Plugin находит где протокол был установлен, а где был вызван, какой функцией он используется и в какой части кода объявляется. На основе этой структуры плагин создает граф, в котором пользователь может интерактивно двигаться по всей прошивке, находя использование протокола в разных EFI файлах.

### 3. Установка
+ Установите новую версию [Ghidra 9.2](https://github.com/NationalSecurityAgency/ghidra) из исходников
+ Установите переменную окружения ```GHIDRA_INSTALL_DIR```
+ Windows (для Linux те же самые шаги):
```
.\gradlew.bat
cp .\dist\* $Env:GHIDRA_INSTALL_DIR\Extensions\Ghidra\
```
+ Откройте Ghidra и в окне проекта нажмите ```File > Install Extensions```
+ Выберите ```EfiGraphPlugin``` и перезапустите Ghidra
+ Выберите подготовленный проект ```File > Restore Project``` и выберите .gar файл из ./data
+ Запустите файл e5373 > Window > Struct Efi
