---
layout: post
title:  "Avast Anti-Virus privileged arbitrary file create on virus quarantine (CVE-2023-1585 and CVE-2023-1587)"
date:   2023-04-26 13:00:00 +0300
categories: posts
---

# 0x00: Introduction

I'm not a big fan of [privileged file operation abuse](https://offsec.almond.consulting/intro-to-file-operation-abuse-on-Windows.html), 
because such vulnerabilities are usually quite trivial. But there are attack surfaces where you really want to find a vulnerability - 
because it seems difficult due to the great attention of developers and researchers to it, the old age of the feature and presumable 
comprehensive testing, as well as its prevalence throughout the entire line of Products - that, due to the nature of the researched feature, 
it is necessary to search for vulnerabilities of exactly this class. An example of such attack surface is undoubtedly the functionality 
of removing malware in Anti-Viruses - the main and most important feature of any Anti-Virus, in fact its "showcase". And I decided to look 
for similar vulnerabilities in the malware removal engine (also known as "quarantine") of 
[Avast Free Antivirus](https://www.avast.com/free-antivirus-download#pc). Avast is a fairly widespread Product so that a vulnerability 
in it affects a large number of machines, it is developed quite responsibly in terms of security, and besides, similar vulnerabilities 
have already been fixed in it not so long ago ([rack911labs research](https://rack911labs.ca/research/exploiting-almost-every-antivirus-software/) 
and [SafeBreach research](https://www.safebreach.com/resources/safebreach-labs-researcher-discovers-multiple-zero-day-vulnerabilities/)). 
My end goal was to execute code in the SYSTEM context as a result of abuse the malicious file removal mechanism. So the research didn’t 
seem like a cakewalk at first – that would be more interesting! Below is the report "as-is" I sent to the Avast development team to fix 
the vulnerabilities found.

# 0x01: High-level overview of the vulnerability and the possible effect of using it

Avast Anti-Virus since ver. 22.3.6008 (I didn’t check previous versions, but it is very likely that they are also vulnerable), when a 
file virus is detected, deletes the file in the context of the SYSTEM account. To mitigate file redirection attacks, it checks the entire 
path for any types of links, converts the path to path without links, and only then deletes the file. However, path checking and file 
removing is not atomic operation, so this algorithm has TOCTOU vulnerability: by manipulating with path links attacker can redirect 
service’s operations and delete arbitrary file/directory. This vulnerability has been assigned 
[CVE-2023-1585](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2023-1585).

Although deleting an arbitrary file/directory is not in itself a critical vulnerability, this bug can be upgraded to code execution as 
SYSTEM. For this attacker needs to use the bug to delete the contents of directory `"C:\ProgramData\Avast Software\Avast\fw"` and then 
delete directory itself. And thereafter restart the main process (`AvastSvc.exe`) via reboot or crash as implemented in PoC. On starting, 
if aforementioned directory does not exist, service recreates it with permissive DACL – full access for Everyone. At the end attacker 
just need to call RPC-method that will execute privileged 
[`CopyFile()`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfile) in fully attacker-controlled directory. 
Such privileged `CopyFile()` gadget obviously leads to arbitrary file write and respectively code execution as SYSTEM. Service crash 
issue has been assigned [CVE-2023-1587](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2023-1587), other problems have been classified 
as weird behavior.

# 0x02: Root Cause Analysis

On file virus `(2)` detecting Avast Anti-Virus (AV) removes the file in the context of the SYSTEM account. This is quite dangerous since by 
manipulating links in a controlled path attacker can provoke a situation where anti-virus service deletes the wrong file. Avast’s 
developers are aware of this risk and therefore AV service tries to create file with random name in same directory. It mitigates junction 
creation because junction can be created only in empty directory (symbolic links need admin rights, hardlinks are not dangerous for file 
delete operations - thus they are out-of-scope attacker’s tools). But if attempt to create file with random name failed `(4)` AV service 
continues to realize own algorithm. So this mitigation is optional because attacker can simply set deny `FILE_ADD_FILE` ACE for SYSTEM on 
the parent directory `(1)`.

![QuarantineExploit 1]({{ site.url }}/assets/images/avast-privileged-arbitrary-file-create-on-quarantine/QuarantineExploit_1.png)

Then AV main service checks the entire path to virus for any types of links `(5)`, converts the path to path without links, and only next 
deletes the file. AV service makes these actions to mitigate file redirection attacks. But without successfully created file with random 
name parent directory of virus is not locked from creating junction in its place.

![QuarantineExploit 2]({{ site.url }}/assets/images/avast-privileged-arbitrary-file-create-on-quarantine/QuarantineExploit_2.png)

Between previously described path checks and subsequent description of file deletion exists time window, when attacker can redirect path to 
another destination. This time window is quite short, but attacker can extend it. After path checking and before file deletion `AvastSvc` 
writes logs `(6)` to logfile named `"C:\ProgramData\Avast Software\Avast\log\Cleaner.log"`. Therefore, if attacker sets RWH-oplock `(3)` on 
`Cleaner.log`, it blocks execution of deleting virus algorithm and attacker can reliably redirect `(7)` parent directory of virus to 
previously inaccessible location. Good news is that at time when the oplock triggers, handles of files inside the directory are not open.

![QuarantineExploit 3]({{ site.url }}/assets/images/avast-privileged-arbitrary-file-create-on-quarantine/QuarantineExploit_3.png)

After directory switching main AV service following symbolic links deletes arbitrary file/directory `(8)` that attacker wants. Moreover 
thanks to service’s privileges and `CreateFile()` flags attacker can remove even 
[WRP](https://learn.microsoft.com/en-us/windows/win32/wfp/about-windows-file-protection)-protected files: `TrustedInstaller` owned files 
accessible with READ-only rights for SYSTEM.

![QuarantineExploit 4]({{ site.url }}/assets/images/avast-privileged-arbitrary-file-create-on-quarantine/QuarantineExploit_4.png)

Putting all the steps together, for successful exploitation arbitrary file/directory delete (CVE-2023-1585) we need to do the following:

1.	Create directory `".\Switch"` with restrictive DACL (deny `FILE_ADD_FILE` ACE for SYSTEM) and test EICAR virus `".\Switch\{GUID}.dll"`;
2.	Create oplock on `"C:\ProgramData\Avast Software\Avast\log\Cleaner.log"` and wait for test virus will be quarantined;
3.	When oplock triggers, remove test virus `".\Switch\{GUID}.dll"` and switch parent directory with mount point to native symbolic link, 
e.g. mount point `".\Switch" -> "\RPC Control"` and native symbolic link `"\RPC Control\{GUID}.dll" -> "??\C:\Windows\System32\aadjcsp.dll"`;
4.	Release the oplock, wait couple of seconds, then make sure `"C:\Windows\System32\aadjcsp.dll"` was deleted.

Arbitrary file/directory delete is not high-impact vulnerability, usually it leads only to DoS. However, there exist approaches to upgrade 
this low-impact bug to code execution as SYSTEM - [here](https://secret.club/2020/04/23/directory-deletion-shell.html) and 
[here](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks). The 
former is already fixed on modern operating systems, while the latter is not reliable due to exploited race condition. So it was decided to 
find own yet unpatched 100%-reliable way to improve impact of this bug.

Code path that can help upgrade file/directory delete to code execution was found in Avast’s codebase. On starting if 
`"C:\ProgramData\Avast Software\Avast\fw"` directory does not exist, service `AvastSvc.exe` creates it with permissive DACL – full access 
for Everyone.

Waiting for a computer or service restart can take a long time, so null dereference bug (CVE-2023-1587) was found in RPC-interface named 
`"aswChest"` with UUID `"c6c94c23-538f-4ac5-b34a-00e76ae7c67a"`. When attacker calls `Proc3` to add file to the chest, he must specify an 
array of key-value pairs (so-called file properties), and if property name (`*propertiesArray` on the image) is null, service immediately crashes.

![IDA null deref]({{ site.url }}/assets/images/avast-privileged-arbitrary-file-create-on-quarantine/IDA_null_deref.png)

As it was already said after restart Avast main service creates `"C:\ProgramData\Avast Software\Avast\fw"` directory, if it does not exist, 
with very permissive DACL – full access for Everyone. And for the attacker, it remains to find a code that manipulates the files in this 
directory in such a way that it will allow you to get an arbitrary file write primitive. It can be various variants of a suitable code patterns, 
but it was found code path that implements `*.ini` files reset inside directory. This code is reachable from RPC-interface named `"[Aavm]"` 
with UUID `eb915940-6276-11d2-b8e7-006097c59f07`. When attacker calls method with index 58, service copies, for example, file `"config.ori"` 
to `"config.xml"` inside directory `"C:\ProgramData\Avast Software\Avast\fw"`. Such gadget is sufficient to obtain a primitive "arbitrary file write".

Last and also probably least – Avast AV prevents access to own RPC-interfaces for untrusted processes. This is implemented as part of a 
self-defense protection mechanism. On allocating RPC-context for further communication with interface RPC-server checks client is trusted 
and only in this case creates valid handle for the client. To bypass this restriction was implemented self-defense bypass based on 
[`SetDllDirectory()`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setdlldirectoryw) for child `AvastUI.exe` 
process configuring and subsequent inject via dll-planting. I don't want to go into the details of this topic here, but you can check it out 
in the source code of the [PoC](https://github.com/the-deniss/Vulnerability-Disclosures/tree/main/Common/SelfDefenseBypassV2).

By chaining both vulnerabilities (CVE-2023-1585 and CVE-2023-1587) into a chain, attacker could obtain arbitrary file write primitive:

1.	Using CVE-2023-1585 delete target file, the contents of directory `"C:\ProgramData\Avast Software\Avast\fw"` and then delete directory itself;
2.	Bypass self-defense and call `Proc3` of RPC-interface `"aswChest`" to crash and restart main service (CVE-2023-1587);
3.	Make sure directory `"C:\ProgramData\Avast Software\Avast\fw"` is now Everyone full accessible;
4.	Create mount point to native symbolic link, e.g. mount point `"C:\ProgramData\Avast Software\Avast\fw" -> "\RPC Control"` and native symbolic 
links `"\RPC Control\config.ori" -> "??\C:\Users\User\Desktop\PoC\pwn.txt"`, `"\RPC Control\config.xml" -> "??\C:\Windows\System32\aadjcsp.dll"`
5.	Call `Proc58` of RPC-interface `"[aswAavm]"` to trigger execution privileged `CopyFile()` in `"C:\ProgramData\Avast Software\Avast\fw"` directory;
6.	Make sure `"C:\Windows\System32\aadjcsp.dll"` was successfully replaced.

# 0x03: Proof-of-Concept

The full source code of the PoC can be found on my [github](https://github.com/the-deniss/Vulnerability-Disclosures/tree/main/CVE-2023-1585%20%26%20CVE-2023-1587/).

Steps to reproduce:
1.	Copy `AswQuarantineFileExploit.dll` to target virtual machine where Avast Free Anti-Virus is already installed;
2.	Run `powershell.exe` and call `rundll32.exe` with DLL `AswQuarantineFileExploit.dll`, exported function `Exploit` and two arguments: 
1st – the name of a file that replaces the file specified by 2nd argument, 2nd - the name of the file being replaced. Example of `rundll32` command line:
```
rundll32 .\AswQuarantineFileExploit.dll,Exploit C:\Users\User\Desktop\PoC\pwn.txt C:\Windows\System32\aadjcsp.dll
```
The exploit can as well create file if it does not exist and overwrite files owned by `TrustedInstaller` and accessible only for `READ` for SYSTEM account.
3.	Make sure file passed as 2nd argument was successfully replaced with file passed as 1st argument.

And below is demo of the PoC:

<video id="aswquarantinefileexploitdemo" preload="none" width="740" height="480" poster="{{ site.url }}/assets/poster/AswQuarantineFileExploit_demo.png" controls>
    <source src="{{ site.url }}/assets/videos/AswQuarantineFileExploit_demo.mp4" type="video/webm">
    <p>Your browser doesn't support HTML video. Here is a <a href="{{ site.url }}/assets/videos/AswQuarantineFileExploit_demo.mp4">link to the video</a> instead.</p>
</video>

*Note: It’s worth noting that PoC code is adapted for Avast Free Antivirus 22.5.6015 (build 22.5.7263.728). This is important, because the exploit intensively 
uses RPC interfaces, and the layout of the RPC interface may change slightly between Product versions.*

Getting code execution as SYSTEM from arbitrary file write primitive is quite trivial (e.g. you can use that 
[trick](https://github.com/blackarrowsec/redteam-research/tree/master/LPE via StorSvc)), so this step is not implemented in the PoC and is not covered in this report.

# 0x04: Disclosure Timeline

- 25-06-2022
Initial report sent to Avast.

- 03-10-2022
Initial response from Avast stating they got displaced my report and are now being reviewed it.

- 19-10-2022
Avast triaged the issue reported as a valid issue and redirected me to the [NortonLifeLock](https://www.nortonlifelock.com/us/en/contact-us/report-a-security-vulnerability/) 
bug bounty portal.

- 27-10-2022
Norton triaged the issue reported as a valid issue and is starting work on a fix.

- 15-12-2022
Norton released patched version of product and is requesting retest of the implemented fix.

- 09-02-2023
I reported to Norton that fixes were incomplete and should be reworked.

- 02-03-2023
I retested new fixes and approved they were correct.

- 19-04-2023
Norton registered CVEs and published [advisories](https://support.norton.com/sp/static/external/tools/security-advisories.html).

- 26-04-2023
This post has been published.
