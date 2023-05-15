---
title:  "Avast Anti-Virus privileged arbitrary file create on virus restore (CVE-2023-1586)"
date:   2023-05-15 10:30:00 +0300
categories: posts
excerpt: >-
  And today I'm sharing the report describing the vulnerability (CVE-2023-1586) in Avast file restore functionality and exploitation 
  of this vulnerability to execute arbitrary code in the "NT AUTHORITY\SYSTEM" context
header:
  og_image: /assets/images/avast-privileged-arbitrary-file-create-on-restore/avast-smashed-glass.png
---

## 0x00: Introduction

In the [previous post](https://the-deniss.github.io/posts/2023/04/26/avast-privileged-arbitrary-file-create-on-quarantine.html), we talked 
about how [Avast Free Antivirus](https://www.avast.com/free-antivirus-download#pc) "awkwardly" removes malware and how an attacker, by 
chaining CVE-2023-1585 and CVE-2023-1587, was able to execute arbitrary code in the SYSTEM context. And it is quite obvious to assume 
that similar problems can be in the virus restore functionality. And today I'm sharing the report describing the vulnerability 
(CVE-2023-1586) in Avast file restore functionality and exploitation of this vulnerability to execute arbitrary code in the 
"NT AUTHORITY\SYSTEM" context.

## 0x01: High-level overview of the vulnerability and the possible effect of using it

Avast Anti-Virus since ver. 22.3.6008 (I didn’t check previous versions, but it is very likely that they are also vulnerable), when user 
requests restore of a file virus, creates the file in the context of the SYSTEM account. To mitigate file redirection attacks, it checks 
the entire path for any types of links, and if the path contains link, terminates operation with error. However, path checking and file 
restoring are not atomic operation, so this algorithm has TOCTOU vulnerability: by manipulating with path links attacker can redirect 
service’s operations and create arbitrary file. This vulnerability has been assigned 
[CVE-2023-1586](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2023-1586).

## 0x02: Root Cause Analysis

On file virus restoring Avast Anti-Virus (AV) create the file in the context of the SYSTEM account. AV main service checks the entire path 
to parent directory for any types of links `(2)`, and if the path contains link, terminates operation with error. AV service makes these 
actions to mitigate file redirection attacks. But between path checking and subsequent file creation exists time window, when attacker 
can redirect path to another destination. This time window is quite short, but attacker can extend it. After path checking and before file 
restoring `AvastSvc` service reads metainfo from encrypted sqlite-database named `C:\$AV_ASW\$VAULT\vault.db`. Therefore, if attacker sets 
RWH-oplock `(1)` on `vault.db`, it blocks execution of restore virus algorithm and attacker can reliably redirect `(3)` parent directory of 
restored virus to previously inaccessible location.

![RestoreExploit 1]({{ site.url }}/assets/images/avast-privileged-arbitrary-file-create-on-restore/RestoreExploit_1.png)

After directory switching main AV service following symbolic links restores arbitrary file `(4)` that attacker wants. It's worth noting 
that the bug only allows to create new files in arbitrary location and not overwrite already existing files.

![RestoreExploit 2]({{ site.url }}/assets/images/avast-privileged-arbitrary-file-create-on-restore/RestoreExploit_2.png)

Thus for successful exploitation arbitrary file/directory create (CVE-2023-1586) we need to do next steps:

1. Create directory `.\Switch` and a test EICAR virus `.\Switch\{GUID}.dll`;
2. Wait for the test virus will be quarantined;
3. Create an oplock on `C:\$AV_ASW\$VAULT\vault.db`;
4. Bypass self-defense and call `Proc82` of RPC-interface `[aswAavm]` to restore file;
5. When oplock triggers, switch parent directory with mount point to native symbolic link, e.g. mount point `".\Switch" -> "\RPC Control"` 
and native symbolic link `"\RPC Control\{GUID}.dll" -> "??\C:\Windows\System32\poc.dll"`;
6. Make sure `C:\Windows\System32\poc.dll` was created.

## 0x03: Proof-of-Concept

The full source code of the PoC can be found on my [github](https://github.com/the-deniss/Vulnerability-Disclosures/tree/main/CVE-2023-1586/).

Steps to reproduce:
1. Copy `AswRestoreFileExploit.dll` to target machine where Avast Free Anti-Virus is already installed;
2. Run `powershell.exe` and call `rundll32.exe` with DLL `AswRestoreFileExploit.dll`, exported function `Exploit` and two arguments: 
1st – the name of a file that contains content the file specified by 2nd argument, 2nd - the name of the file being created. Example of `rundll32` command line:
```
rundll32 .\AswRestoreFileExploit.dll,Exploit C:\Users\User\Desktop\PoC\pwn.txt C:\Windows\System32\poc.dll
```
3. Make sure file passed as 2nd argument was successfully created and contains content of file passed as 1st argument.

**Note:** The exploit can only create new file in arbitrary location and cannot overwrite already existing files.
{: .notice--info}

And below is demo of the PoC:

<video id="aswrestorefileexploitdemo" preload="none" width="740" height="480" poster="{{ site.url }}/assets/poster/AswRestoreFileExploit_demo.png" controls>
    <source src="{{ site.url }}/assets/videos/AswRestoreFileExploit_demo.mp4" type="video/webm">
    <p>Your browser doesn't support HTML video. Here is a <a href="{{ site.url }}/assets/videos/AswRestoreFileExploit_demo.mp4">link to the video</a> instead.</p>
</video>

**Note:** It’s worth noting that PoC code is adapted for Avast Free Antivirus 22.5.6015 (build 22.5.7263.728). This is important, because the exploit intensively uses RPC interfaces, and the layout of the RPC interface may change slightly between Product versions.
{: .notice--warning}

As I've already said, getting code execution as SYSTEM from arbitrary file write primitive is quite trivial (e.g. you can use that 
[trick](https://github.com/blackarrowsec/redteam-research/tree/master/LPE via StorSvc)), so this step is not implemented in the PoC and is not covered in this report.

## 0x04: Disclosure Timeline

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
I confirmed that fix is correct.

- 19-04-2023
Norton registered CVEs and published [advisory](https://support.norton.com/sp/static/external/tools/security-advisories.html).

- 15-05-2023
This post has been published.
