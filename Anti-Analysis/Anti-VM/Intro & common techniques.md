# _Anti-VM Overview

_Had already talked about Anti-Debug techniques, but now, we'll cover Anti-VM (Anti-VirtualMachines), these use it's really interesting because, most of them are not based on hard techniques or uses on internal structures like Anti-Dbg, on Anti-VM, we will see certainly tricks checking computer states and related, will be more logical in my opinion if you know how a VM and these techniques usually works, when you know a few of these, don't will be difficult for you detect it. Some of these will be similar but I will show you how it works and how to bypass each of them. A few Anti-VM techniques can be used on Anti-Sandbox, switching paths, processes, and so on, applying logic, if you know Anti-VM, you'll be able to detect quite a few of the Anti-Sandbox._

# _Anti-VM techniques

These techniques can be divided into several groups, We'll cover several of them, first of all, the most common tricks, hunt of processes, paths, keys and services, later, based on computer checks, afterwards instructions and finally a summary. I'll not talk a lot about check times because you can learn about these on Anti-Dbg, and it will be repetitive.

The VM are usually used on computer science, on Malware Analysis is not an exception, once the Malware is launched on a VM, internally, will not work quite the same as your host, some paths, keys o services will be different and the Malware writers knows that we use VM to analyze.

### ¯_Based on Paths, Keys, Processes & Services

When we are using a Virtual Machine, we use Vmware, VirtualBox or similars, these tools installs some services, open processes or register keys on the virtualized computer and this is really easy to track by a Malware writter. A example of these is when we are using VirtualBox, normally, we install drivers as VBoxTray, and these will be a service and running like a process.

A way to locate it could be taking an process snapshot ([CreateToolhelp32Snapshot](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)) and looking for VBoxTray.exe, if you are using VMware you can see vmnat.exe, but as you can see, that's similar like some Anti-Dbg techniques, later I will show more processes or services in which you need have to be careful.

At the following image, you can see an example, at this Malware, it tryies to hunt several processes, on his black list we can see VBoxService and VBoxTray

![10000000000001E20000006EA9CC853C23A96B32](https://user-images.githubusercontent.com/91592110/136978613-44ea1b84-1ce4-45af-b465-2a6b0e2d6b4d.png)

![10000000000003540000005CB158BBF84DEAF09C](https://user-images.githubusercontent.com/91592110/136978710-b4cf601f-cdda-4221-a8f9-e02e700ad585.png)

![100000000000035D000000486080AF09B8A2E64B](https://user-images.githubusercontent.com/91592110/136978740-520927b7-c8ee-4f10-a66b-2bf3be06bc69.png)

As you can imagine, it's easy to skip this tricks, you can find some of techniques like hunting paths or RegKeys, when a program installs on our computer, it needs configuration files or folders to save itself and this is a useful target to Malware Writers.

At the following image, we can see some elements used on Anti-VM like Guest Additions (Graphic Drivers of VBox), normally we install these and it's a good one to Malware Writters to detect your VM, we have others like Regkeys (Sys bios version or any that contains VBOX)

![1000000000000200000000D256643742A949BAA8](https://user-images.githubusercontent.com/91592110/136978836-6dcc68cc-2864-466a-8184-ab7c588bfd8e.png)

While we are debugging, we will se how loads strings that belong to RegKeys of VBox, at this point, the Malware have a blacklist with Keys, Processes or services related with VM and it uses Stack to load these, usually checks it using strings on data or using a Json that will generate and checking all of them 

![10000000000001FA000000102BC1F1FE44852067](https://user-images.githubusercontent.com/91592110/136978881-c2a41f18-3472-4af5-9409-edc96d65e03e.png)

Once have loaded all of them, it will check if any of these appears, it can be used in any way that you imagine, installation folders, windows, Anti-Virus...

#### ¯_Bypass

It will be easy, we have a lot of options, I recommend you change the cmp on the debugger when the Malware test if a data matches with his blacklist or if it's not hardcoding strings or data while it's running and we see the name of processes or services we can change these on memory (Like in the image), using this we don't need to be care if it compares, test or something, we change the name value on memory and it won't match ever (Alike that imports on data names related with the VM). If it's using a Snapshot, change the process name. As option, you can uninstall Guest Additions or related VMware/VBox tool and you will not need to dodge as much tricks (But usually the Malware Writers use a lot of techniques at once and it won't do you much good to uninstall)

![1000000000000177000000257D3C56F3300D4280](https://user-images.githubusercontent.com/91592110/136979010-e838bcdc-2326-4dc3-b002-d1b50d959f30.png)

![10000000000001730000002317AB111E342383FC](https://user-images.githubusercontent.com/91592110/136979020-d37d29c2-48bd-4327-a544-5e59d32cca72.png)

### ¯_Based on Computer Checks

Last technique or group of techniques are polyvalents and can be used a lot, using APIs and WMI you can easy check or hunt programs or services too, at this technique we will focused on looking for features of our computer, because although the VM simulates a real computer, in certain aspects it's not or has elements that give it away.

There're a lot of elements that the VM is not equal with a real computer, an examples of that is a MAC, ports, BIOS, etc. Seems similar but it's not like a real computer features, a list of these could be:

> - MAC (Depending VBox/VMware you will have a MAC indicative of a VM)
> - CPU (Several as, manufacturer, temperature, cycles, threads...)
> - BIOS (Signed by the VM)
> - Motherboard (Manufacturer, ID...)
> - HardDiks (Types)
> - Memory (APIs like [GlobalMemoryStatusEx](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex))

Logically, if we think about previous list, that a virtual processor will not have temperature or the components will be signed by the VM it's not uncommon, we'll find a lot of APIs used for Anti-Analysis or to looking for User/Computer information and send it or use to detect our analysis, also, it can be used by Ransomware, Spyware, and so on. Some APIs, that can help you to find this:

> - [EnumServicesStatusW](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusw) (Hunts services related with VM)
> - Several [iphlpapi.h](https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/) like GetAdaptersAddresses (To find IP and others network elements)
> - [GetVolumeInformation](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationa), [GetDriveType](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypea) (Shared folders used by VM and others, you can use some [fileapi.h](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/) functions to looks for paths too)
> - [RegOpenKey](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeya) (Well, a lot of winreg.h functions to hunt RegKeys related with VM)

To these APIs you can add WMI in which you can looks for IP, MAC, BIOS, and so on...

An example of these techniques could be the BIOS hunt, using the WMI class ([WIN32_BIOS](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-bios)), we can detect some HW components 

![10000000000002390000001BFF1FFD3A3CB13018](https://user-images.githubusercontent.com/91592110/136979783-41b7343d-3b8c-40b0-a5d6-0613dbb00afd.png)

![1000000000000115000000401124C5B2D7C4130B](https://user-images.githubusercontent.com/91592110/136979836-18440d9c-bbf9-4dd9-b58f-b0bde0d85a52.png)

Can be check some options, like name, manufacturer, model...

![10000000000001E7000000A6E160696E95979512](https://user-images.githubusercontent.com/91592110/136979899-879f86de-a307-44cc-826b-f86ba5f4bb28.png)

On this picture, you can see how tryies to check the version, usally, using a VM you will not have a BIOS, and the value will be 0 or NULL. Using cimv2:Win32_BIOS we will see VBox strings, later, checks if the value is less than a number or NULL, but we don't have any SerialNumber because we use VM

![10000000000002D3000000732260BD2607A68A4A](https://user-images.githubusercontent.com/91592110/136979969-31a7f31c-eff4-4e5a-bdda-568b3cd4aef6.png)

![10000000000000960000004B32780A394DB7CE37](https://user-images.githubusercontent.com/91592110/136980038-2b722451-c338-4274-a121-34dce1c0f748.png)

![10000000000001880000004A6FCF8B1FFF97E081](https://user-images.githubusercontent.com/91592110/136980145-8ac46791-a538-4ead-8371-03df70bfd395.png)

![10000000000002680000009F0E9975184C16E0FC](https://user-images.githubusercontent.com/91592110/136980170-d6b13807-8051-4e1d-a615-30a7149b4bb8.png)

As I was saying, there are many ways to check it, another example is looking for fields that contais VBOX or VMware

![10000000000004090000005D921AA10FE44E3629](https://user-images.githubusercontent.com/91592110/136980332-3449053b-3b2c-48e8-9e7b-b4f2a40d7d6c.png)

We can use too the motherboard to detect the VM, using the [Win32_MotherboardDevice](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-motherboarddevice) catching strings like Oracle or VBox on the manufacturer 

![10000000000001F6000000527FF8D35D0DC45AF8](https://user-images.githubusercontent.com/91592110/136980392-b904b2e0-97fd-42f4-bd75-b5f6d53b579f.png)

Also, we can use the Disk to catch the VM, looking for paths, sizes using APIs ([GetDiskFreeSpace](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespacea)) or shared folders, usually used on VM to share information among host and virtualized machine

![10000000000001D600000060A6858FB8676A7ACB](https://user-images.githubusercontent.com/91592110/136980542-6cfcf9d2-cdee-48b3-8614-2acdbf0b0b71.png)

![100000000000034700000048E5DC4F3D6CCFA51F](https://user-images.githubusercontent.com/91592110/136980560-5cf51748-32eb-4554-bf24-309d25c8654c.png)

We have many more similar techniques based on HW checks, we can try to do a blacklist with predefined MACs of VM, network card, CPU temperature, and so on. You can find many but you just've to think how it works.

#### ¯_Bypass

We have many techniques but the bypass may be the same, if you see a blacklist of MAC, change on memory the values or change your MAC using your VM launcher, avoid shared folders, on values checks like Manufacturers or SerialNumers you can modify it when checks it or erase all the VBox/VMware strings that you'll see while you are debugging to minimize the Anti-Analysis techniques, always the best way is not change the program flow if you can change flags, values or data in memory.

### ¯_Based on Instructions: sidt, sgdt & sldt

Exists more complex techniques focused on Anti-VM, before we was talking about more "logical" detection tricks. At Anti-Dbg post we covered time checks or CPU cycles, you can find a lot of these techniques related with the Anti-Analysis.

Now we will talk about "Pill" (Red-Pill & No-Pill) Anti-VM tricks, to understand how it works it's more difficult than the latest techniques, but don't panic! When we are using a VM we will have a environment which in fact is not exactly a real host (although it seems) so, some instructions will be emulated because it can't be executed in the same way as if it were a real one... In other words... If we launches certainly instructions in our VM we will obtain different values in practice.

This happens because some registers (IDTR, GDTR & LDTR) interact with a structures (IDT, GDT & LDT respectively) and contains information like structures addresses, sizes, and so on. When we are using a VM the OS needs to relocate these registers and the locations of these will be different if you are using a VM (Depends on Virtualization Software that you use) or a real host (Will be different depending on OS version), using any of these registers we can know if the computer is being virtualized or not. Malware writters will use sidt, sgdt and sldt instructions which will be represent the structures and registers IDT-IDTR, GDT-GDTR and LDT-LDTR respectively.

An example of this technique using Red-Pill is the next picture, we can see the use of sidt instruction to add bytes at the IDt struct, later it compares with a constant (0xFF), it depends if you are using VMware, VBox and so on, now we are working with VMware. This constants refer to the base address of IDT, it will be different if we are virtualizing or not because te VM needs to re adjust these registers, this technique used sidt and refer to IDTR register.

![100000000000026A0000010030B5F8F7A1BBCF4B](https://user-images.githubusercontent.com/91592110/136980776-0e8d7103-74d6-4bf6-accc-97f988533239.png)

You can find more constants depending on Softwares, OS version, and so on:

![10000000000000C30000006515EB667056BFF808](https://user-images.githubusercontent.com/91592110/136980867-24996aa3-cd06-4a32-ba40-2165ea120969.png)

The No-Pill techniques based on sldt and sgdt may be check a constants based on hexadecimal values grather than 0DXXXXXXXh, it works similar, looks for a base address and compare

![10000000000000C90000004B039CC965A64D44EE](https://user-images.githubusercontent.com/91592110/136980935-92ac0f08-e000-4409-90ea-35e6041a6313.png)

![10000000000000BE00000031C11760E4C4B645DA](https://user-images.githubusercontent.com/91592110/136980940-91373a51-a570-4b58-a5c9-a3d6d1a21840.png)

#### ¯_Bypass

Most of Pill techniques will use a cmp or a test to verify the base address or to catch the VMware or VBox register value (0xe8... 0xff...), so I recommend to change the value on memory or switch to NOPs the Pill function... These tricks usally are using single-core so, to avoid that it's advisable to launch the VM using multi-core and specifically at No-Pill dissable acceleration box.

# ¯_Summary

We covered several Anti-VM techniques, you can find more but these are usually the most recurrent (At least for me...) I leave you a scheme to help you find the techniques easily:

![1000000000000452000001C5593D790413A7CB2C](https://user-images.githubusercontent.com/91592110/136981044-e5dfdeb8-f6a4-4a5f-adfa-f0bf95f6fd1c.png)

Being the techniques most recurrent, the Malware evolves and change, some tricks may be perfectioned or you can see new tricks, but if you are skilled at the most common Anti-Analysis techniques, will not be difficult for you catch new ones.

> :t-rex: [vc0=Rexor](https://github.com/vc0RExor)  :detective:
