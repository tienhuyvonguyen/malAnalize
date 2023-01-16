# Conti Ransomware Report

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled.png)

Date: 17/01/23

Ransomware Family: REvil - Sodinokibi

Target: [Conti Ransomware v2 with source code](https://virusshare.com/file?eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301fe)

# Overview

![Cre: chuongdong.com](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%201.png)

Cre: chuongdong.com

Quick overview about Conti Ransomware. The picture above credit from [chuongdong.com](http://chuongdong.com) shows a good overall about how Conti Ransomware run and ransom user data. It’s worth to note that Conti is called a modern Ransomware which it contains much more advance techniques that evade itself from AV ( anti-virus ) and also, anti debugging and reverse engineering, make it harder for malware analyst and reverser to figure it out. Moreover, some of advance methods such as networked SMB target via command line, 32 CPU threats encryption and abuse Windows Restart Manager is a signature of this new type of Ransomware that make it stand out from the rest of the ransom world.

Conti come with the full source code of 2nd and 3rd version of the ransomware, including PE file and DLL file, also, you can built the PE file on your own with source code provided but be careful and pay attention to the version of your built tools.

Till now, Conti ransomware source code been leaked out there in the internet, but I will focus on the 2nd version in this report.

# IOCS

Hashes:

SHA256: eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301fe

MD5: 

c63e93572907b6e36477fed8ba2e8736

Related email addresses:

[flapalinta1950@protonmail.com](mailto:flapalinta1950@protonmail.com)

[xersami@protonmail.com](mailto:xersami@protonmail.com)

[eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301fe (MD5: B7B5E1253710D8927CBE07D52D2D2E10) - Interactive analysis - ANY.RUN](https://app.any.run/tasks/91c78dd5-41e5-4979-a7be-0fe3d9814ea1)

[https://www.virustotal.com/gui/file/eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301fe/detection](https://www.virustotal.com/gui/file/eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301fe/detection)

[https://www.joesandbox.com/analysis/656759/0/html#deviceScreen](https://www.joesandbox.com/analysis/656759/0/html#deviceScreen)

# Ransom Note

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled.png)

From the above picture, I already include a ransom note, entry point of the ransom and the extension it use to mark the ransom files including ransom note at any places that the ransomware compromised. 

# Dependencies

From static perspective, we may want to run CFF Explorer to see what is including inside the ransomware, where is it entry-point and which DLLs it imported. 

The ransomware imports 3 DLLs ***Kernel32.dll, User32.dll, and WS2_32.dll*** as visible DLLs. 

Entry point of the PE is 0x5053 as shown in the last section.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%202.png)

# PE Layout

Section table not contains any strange section

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%203.png)

We may want 1 more time go around with fileInsight to see an overall picture of the ransomware.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%204.png)

Next, I want to start DIE ( detect it easy ) to export strings from the ransomware. Strings provide amazing information about the file we want to analyze as you can see beneath.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%205.png)

As you can see, cyan stand for some dlls we already detected, orange stand for some functions the ransomware are implemented and purple contains some kind of note and a contact email address.

# Code Analyze

## Statically

### Source Code Analyze

We start in the source code perspective, to see what really running underground. Here is the main function:

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%206.png)

Right in the first line after initialize variable, the ransomware call to an API header, the name state its function.

Of course, they must need kernel32.dll to load more other dll, so first they implement the kernel32.dll and then set some def for x64 or x86 architecture.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%207.png)

Go further, we may see the whole list of dll the ransomware want to import the its seek.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%208.png)

And right inside the function they implement some kind of hashing named MurmurHash that serve for the import of libraries. 

Then right after load DLLs, the ransomware want to antiHooking which help it make sure the dlls is not compromise by any cases may occur. [To explain antiHook.](https://malwareandstuff.com/examining-smokeloaders-anti-hooking-technique/)

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%209.png)

Move on to the whiteList, which are programs that the ransomware want to avoid to compromise to make the process smooth and success the ransom.

Then they tend to search for the targets, which is Drives, where stored all the hostage that they want to ransom.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2010.png)

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2011.png)

Noted that this Conti ransomware is target not only the local data, but it tend to works as a RaaS, which mean Ransomware as a Service. So, it will contains a source code that whole itself perform the scanning, connect and create a network table for the ransomware itself. 

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2012.png)

And of course, to serve the many functions, it come with the command line for advance control over the ransomware.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2013.png)

Then the rest of the main method:

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2014.png)

To get information about the machine its running on, sysInfo is obtained and the ransom use it to determine how many threads it gonna use to success their work.

In threadpool, it will spawn the thread they want to use to speed up the encrypt process and maximize the encrypt process:

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2015.png)

In the next step, which is the advance technique that till now, just some ransomware use is to abuse the VSS service, which stand for Volume Shadow copy Service. [More information](https://blogs.vmware.com/security/2022/09/threat-report-illuminating-volume-shadow-deletion.html) 

Including 6 steps, which I suggest you browse for the code with explain to gain further information. The whole process mainly to archive the task of cleaning up all state that user may find a way to recover their data.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2016.png)

Next, it whitelist which process it will use to serve the ransom.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2017.png)

Then the encryption phases start:

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2018.png)

We will focus on the local encryption:

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2019.png)

From the above picture, threatpool:Start is initialize from soon.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2020.png)

Then from this function. threatHandler will be the function that lead us to the encryption phase which located in locker source code named lock::Encrypt.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2021.png)

From here, the encryption phases is divide into smaller sections based on the size of the file and/or file type.

From now on, we switch to IDA which is disassembler and pseudo-code from decompiler perspective to view this code.

### Pseudo-Code Analyze

First we want to put the ransomware on some kind of cloud sandbox that will automate analyze and observe the ransomware for us, so we can have an overall over the functions and techniques that the ransomware is using. I choose Anyrun to help me:

The report: 

[eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301fe | ANY.RUN - Free Malware Sandbox Online](https://any.run/report/eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301fe/91c78dd5-41e5-4979-a7be-0fe3d9814ea1)

We want to start IDA to begin disassemble the file and decompile the asm code to see what is inside the file and get more information about it.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2022.png)

So right at the entry point of the ransomware, from IDA perspective, we encounter a function that lead us to the IDA view in the left side which contains many LoadLibrary API function from KERNEL32.dll. But from the later part, we go around with CFF and its shows us only 3 dlls is imported, but from here, at least 8 is imported to the PE file at runtime.

Go further down, we are faced with many long mov instructions and a call to functions start with sub_404 & sub_403 in name, and each function all have nearly 80-90% in similar in structure. This may indicate that these function may do the same job but in different way. State that right before each call instruction, it contains a series of mov instruction with hex value, we may guess that this function is trying to resolve and call for some kind of external function/library in silent at the runtime.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2023.png)

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2024.png)

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2025.png)

In pseudo-code view, we may confirm the theory we guessed above.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2026.png)

### Dynamically

To start the dynamic analyze, we want to try to run the ransomware in the native environment let the beast do what it been programed to do.

The following GIF demonstrate how the beast in the wild. 

![demoConti.gif](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/demoConti.gif)

In the rest section, we will fire up IDA in debug mode, this allow the malware to run like in the wild but IDA got our back and help us to analyze the ransomware in instructions, memory and threads view.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2027.png)

Right after press the debugging button, we may see that everything start right away. As you can see below, the import table just expand a tons of libraries that not in our expected.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2028.png)

And over 35 threads already to run

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2029.png)

Go deeper in debugging, we will find the source and sink of the whole program, from IDA View, step by step run over the instruction we may encounter a source of the work flow which find the file and craft the file path for the encryption process to archive.

So, the encryption phase should be the sink, the find file and craft the file path should be the source. Due to the ransomware need to try to encrypt the tons of files, so the process in debugging will repeat like hundred or thousand times with the same steps like descript above with source-sink.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2030.png)

Cause of that, we may find out which is the sink phase and which is a source phase.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2031.png)

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2032.png)

# Unique Techniques

## multi-threads encryption

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2033.png)

Noted from threadPool, the TasksCount is set to reach the maximum Tasks which can up to 15000.

## Networked SMB target

From the main function, we already have the options to choose to ransom over the network via SMB port 445 which come with the full functions to perform the task.

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2034.png)

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2035.png)

## Abuse Windows Volume Shadow Copies

Mimic Ryuk ransomware family but unique action. 

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2036.png)

![Untitled](Conti%20Ransomware%20Report%201309ea2342714db190c4926770a284c7/Untitled%2037.png)

Based on the repot from anyrun above, you may see that vssadmin is called right after the ransomware running.

# References

[https://businessinsights.bitdefender.com/what-are-ransomware-families-and-why-knowing-them-can-help-your-business-avoid-attack](https://businessinsights.bitdefender.com/what-are-ransomware-families-and-why-knowing-them-can-help-your-business-avoid-attack)

[https://blogs.vmware.com/security/2020/07/tau-threat-discovery-conti-ransomware.html](https://blogs.vmware.com/security/2020/07/tau-threat-discovery-conti-ransomware.html)

[https://www.cisa.gov/uscert/ncas/alerts/aa21-265a](https://www.cisa.gov/uscert/ncas/alerts/aa21-265a)

[https://malpedia.caad.fkie.fraunhofer.de/details/win.conti](https://malpedia.caad.fkie.fraunhofer.de/details/win.conti)