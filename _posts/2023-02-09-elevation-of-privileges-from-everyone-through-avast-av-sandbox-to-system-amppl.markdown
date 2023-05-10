---
title:  "Elevation of privileges from Everyone through Avast Sandbox to System AmPPL (CVE-2021-45335, CVE-2021-45336 and CVE-2021-45337)"
date:   2023-02-09 11:00:00 +0300
categories: posts
excerpt: >-
  Today we'll talk about how by adding AV engine sandbox you can open a new attack path and, as a result, let the attacker through the chain of vulnerabilities 
  (CVE-2021-45335, CVE-2021-45336 and CVE-2021-45337) elevate privileges from normal user to SYSTEM with AmPPL protection level
permalink: /posts/2023/02/09/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl.html
---

# 0x00: Introduction

In March 2020 (during quarantine) I researched the security of [Avast Free Antivirus](https://www.avast.com/en-us/free-antivirus-download) ver. 20.1.2397 
and I may have been one of the first external security researchers to explore the product's newest feature – the antivirus (AV) engine sandbox. Today we will
talk about it and I will show how by adding a cool security feature you can open a new attack path and, as a result, let the attacker through the chain of 
vulnerabilities ([CVE-2021-45335](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45335), 
[CVE-2021-45336](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45336) and [CVE-2021-45337](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45337)) 
elevate privileges from normal user to "NT AUTHORITY\SYSTEM" with Antimalware Protected Process Light protection level 
([link](https://web.archive.org/web/20220930184720/https:/www.avast.com/hacker-hall-of-fame/en/researcher-david-eade-reports-antitrack-bug-to-avast-0) to 
description of impact in the now unavailable Avast Hall of Fame. [@Avast](https://twitter.com/Avast), thanks for putting it on a list no one has access to 😉).

# 0x01: Insecure DACL of a process aswEngSrv.exe (CVE-2021-45335)

When searchinging for vulnerabilities my first step (probably like everyone else) is to examine the accessible from my privilege level attack surface. At that 
time I logged in as a normal user (not a member of the Administrators group) and launched the `TokenViewer` application from the well-known 
[NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager) package. And I saw the following picture:

![aswEngSrv.exe in TokenViewer]({{ site.url }}/assets/images/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl/tokenviewer_aswEngSrv.png)

It immediately catches the eye that the current low-privileged user, among the obvious access to applications running in the same context, has access to the 
token of the process running as "NT AUTHORITY\SYSTEM". This is not the default behavior. What can be done with this token? In short, nothing. To elevate 
privileges I would like to impersonate toket or create a process with such a token but due to the lack of privileges for a regular user (`SeImpersonatePrivilege` 
or `SeAssignPrimaryToken`) and another user (`ParentTokenId` and `AuthId`) in the token, we cannot do any of this.

Let's then take a closer look at the process of interest and try to understand what it does:

![aswEngSrv.exe details]({{ site.url }}/assets/images/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl/aswEngSrv_details.png)

It is clear from the description of the binary file that the logic of scanning files has been moved to this process. There are a lot of file formats 
(+packers), including complex formats, parsing takes place in C/C++ – not a memory safe language – and the developers wisely decided to sandbox the process 
which is very likely to be pwned. Thereby reducing the impact from the exploitation of a potential remote code execution (RCE).

> NOTE: I don't know what triggered the release of the antivirus engine sandbox in 2020 and how hastily it came out but perhaps 
> [the vulnerability report and the ported JS interpreter code](https://twitter.com/taviso/status/1237105815414124549) from [@taviso](https://twitter.com/taviso) 
> speeded up its release.

It is logical to assume that the high privileged `AvastSvc.exe` process assigns the task of scanning the contents of the file via inter-process communication (IPC) to 
`aswEngSrv.exe`, and the latter, in turn, scans the data and makes a verdict like "virus" or "benign file". Having dealt with the functionality implemented by this 
process injecting into it does not seem senseless. After all if we can inject into the scanner process we can influence its verdicts and ultimately get the 
ability to delete almost any ("almost" because AVs usually have the concept of system critical objects (SCO) of files that they will never delete. This is 
implemented so that you do not accidentally remove system files) file.

If you look at the [`OpenProcessToken`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken) documentation 
you will see that in order to open a token you must have the `PROCESS_QUERY_LIMITED_INFORMATION` access right on the process. Since `TokenViewer` shows us a token 
it means that it was able to successfully call `OpenProcessToken`, which means that we have some kind of rights to the process. Usually there is no way for the user 
to open processes running as "NT AUTHORITY\SYSTEM". Look at the DACL of the `aswEngSrv.exe` process:

<!--![aswEngSrv.exe DACL]({{ site.url }}/assets/images/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl/tokenviewer_aswEngSrv_SD.png)-->
```
.\accesschk64.exe -p aswEngSrv.exe -nobanner
[4704] aswEngSrv.exe
  RW Everyone
  RW NT AUTHORITY\ANONYMOUS LOGON
  RW APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES
  RW NT AUTHORITY\SYSTEM
```

Obviously with such a DACL you can make an inject for every taste (in the PoC I used the [Pinjectra](https://github.com/SafeBreach-Labs/pinjectra) project). 
Thus using the insecure DACL of the `aswEngSrv.exe` process we can obtain a gadget for deleting arbitrary files as follows:

1. Send the file we want to delete for scanning;
2. Inject the code into the sandboxed process of the AV engine `aswEngSrv.exe` and "say" that the file is malicious;
3. After that the privileged `AvastSvc.exe` service will have to delete the corresponding file.

There is a vulnerability and it is clear how to exploit it but I still want to understand why there is such a permissive DACL on the process object. Is this a 
mistake of the antivirus developers or a strange behavior of the operating system (OS) when creating a child process with a restricted token?

The process and thread DACL are specified by `DefaultDACL` of the primary token of the process. By default the `DefaultDACL` is created by the system adequately and 
developers usually do not need to configure it themselves (many people do not even know about its existence). When creating a restricted token the `DefaultDACL` is 
simply copied from a primary token, and in the case of the `AvastSvc` service it is quite strict by default and contains literally 2 ACEs:

![Restricted token default DefaultDACL]({{ site.url }}/assets/images/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl/restrictedtoken_default_defaultdacl.png)

Only "NT AUTHORITY\SYSTEM" and "BUILTIN\Administrators" access is allowed, and for Administrators this is not full access. But then for some reason the developers 
themselves create the maximum permissive DACL and set it to the restricted token:

![Set permissive DefaultDACL to the restricted token]({{ site.url }}/assets/images/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl/set_restrictedtoken_permissive_defaultdacl.png)

The comment in the code highlights in the SDDL format the value of the security descriptor used in runtime: Full Access for "Everyone", "Anonymous Logon" and 
"All Application Packages". This actually explains why the `aswEngSrv.exe` process has such a DACL.

I also want to make an assumption why the default behavior did not suit the developers and they decided to manually configure the `DefaultDACL`. I have two versions. 
The first is that when a process creates objects, the 
[DACL on them is assigned in accordance with the inherited ACEs of the parent container](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptors-for-new-objects). 
But if there is no container then DACL comes from the primary or impersonation token of the creator. And when `aswEngSrv.exe` was launched with the default 
`DefaultDACL` then after creating its objects it could not reopen them due to the strict DACL. And the second version is that RPC, COM-runtime and other system code 
often tries to open their own process token and if you do not configure the `DefaultDACL`, as the Avast developers did, then the process cannot open its own token 
and the code crashes with strange errors. And this is inconvenient.

# 0x02: Sandbox escape (CVE-2021-45336)

I've never liked arbitrary file deletion vulnerabilities because I don't think the file deletion impact is that interesting in real life. And I want of course the 
execution of arbitrary code in the context of a privileged user. To this end I decided to see what can be achieved by injecting into `aswEngSrv.exe` besides deleting 
files.

In fact this is counterintuitive – from a process with the rights of the current user get into the sandbox to elevate privileges. Because the sandbox by design provides 
the code executing in it uniquely less privileges than the normal user has. The same idea was in the Avast sandbox. Below is a picture with a process token:

![aswEngSrv.exe token before fix]({{ site.url }}/assets/images/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl/aswengsrv_token_before_fix.png)

It can be seen that this is a restricted token owned by SYSTEM. The developers did everything in accordance with chapter 1.2 "Restricting Privileges on Windows" of 
the book ["Secure Programming Cookbook for C and C++" by John Viega, Matt Messier](https://www.amazon.com/Secure-Programming-Cookbook-Cryptography-Authentication/dp/0596003943).
If you do not know this concept I highly recommend that you familiarize yourself with the ideas from the book and now we will look at how restricted token is used 
to create a sandbox in Avast AV. `AvastSvc.exe` crafts restricted token by setting the "BUILTIN\Administrators" SID to 
[`DENY_ONLY`](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-attributes-in-an-access-token), removing all privileges except 
[`SeChangeNotifyPrivilege`](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/bypass-traverse-checking), adding 
restricted SIDs that characterize a normal unprivileged user (you can see it in the picture above), as well as lowering the integrity level to Medium. After that when 
you try to access the securable object from the context of the sandboxed `aswEngSrv.exe` the following process occurs (the algorithm is shown in a very simplified way, 
only to explain how restricted token works):

![Restricted token access check example]({{ site.url }}/assets/images/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl/restricted_token_access_check.png)

The access check takes place in two rounds – for the normal list of SIDs and for restricted -, and the verdict is made based on the intersection of the permissions 
issued in two rounds. The picture shows that in round 1 permission was obtained for `RW`, in the second – only for `R`, which means that the process will not be able 
to get the desired access to `RW`, since `{R, W} ∩ {R} = {R}`.

But at the same time we see that the sandbox is somewhat unusual – launched from "NT AUTHORITY\SYSTEM". What if you can get out of it and at the same time "reset" your 
restrictions and ultimately get the original privileged process token – parent token of the restricted. Let's try to enumerate available resources such as files using 
the following command:

{% highlight PowerShell %}

Get-AccessibleFile -Path \??\C:\ -ProcessName aswEngSrv.exe -Recurse -CheckMode All -AllowPartialAccess -FormatWin32Path`
    -DirectoryAccess AddFile,AddSubDirectory,WriteEa,DeleteChild,WriteAttributes,Delete,WriteDac,WriteOwner`
    -Access WriteData,AppendData,WriteEa,DeleteChild,WriteAttributes,Delete,WriteDac,WriteOwner
{% endhighlight %}

In the code listing above we used the `Get-AccessibleFile` cmdlet to get all filesystem objects on the `C:` drive,into which we can somehow write from the `aswEngSrv.exe` 
privilege level. The result is a list of resources available for a normal user. Interestingly there are 
[such locations](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md#placing-files-in-writeable-paths) that are often used 
to bypass SRP. But from the point of view of privilege escalation this is not notably promising since the straightforward attack of a system service by manipulating 
accessible files or the registry or something else will definitely be very time consuming.

Thus the search for the possibility of elevation through securable objects such as files, registry, processes, thread is not immediately suitable due to the existing 
restrictions that are provided by the restricted token implementation. There remains the option of exploitation IPC – RPC, ALPC, COM, etc. Moreover it is necessary 
that during the IPC request the token is not impersonated, but only checked, for example, for the owner who is quite privileged in our case, and then privileged 
actions are already performed e.g. spawning a child process.

Even earlier I saw the [post](https://itm4n.github.io/localservice-privileges/) by [Clément Labro](https://twitter.com/itm4n) – he wrote that with help of the 
`TaskScheduler` you can return dropped privileges by creating a new task. And even then I had a feeling that the `TaskScheduler` could act as an entity that could 
restore the original token from modified. The article did not explain why it worked there and therefore it was not clear whether this approach would work in our 
case. But nevertheless a hypothesis appeared: what if the restricted token of the `aswEngSrv.exe` can also be upgraded? And I decided to consider this vector as 
a possible sandbox escape.

If you look at the low-level implementation of the `TaskScheduler` interface you can see from the 
[specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931) that to register a task it is enough to call 
the [`SchRpcRegisterTask`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/849c131a-64e4-46ef-b015-9d4c599c5167) RPC method. I tried to do this using 
powershell impersonating the `aswEngSrv.exe` process token and in its context writing a task that should already be running as a non-restricted SYSTEM:

{% highlight PowerShell %}

$process = Get-NtProcess -Name aswEngSrv.exe
$imp_token = Get-NtToken -Process $process -Duplicate -TokenType Impersonation -ImpersonationLevel Impersonation

$action = New-ScheduledTaskAction -Execute "cmd.exe"
$trigger = New-ScheduledTaskTrigger -Once -At 2:55pm
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger

Invoke-NtToken $imp_token { Register-ScheduledTask TestTask -InputObject $task }

{% endhighlight %}

But [`Register-ScheduledTask`](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask?view=winserver2012r2-ps) for some reason does not 
use the impersonation token, probably the work is transferred to the thread pool which "does not know" about impersonation. And so the call happens in the context of the 
process' token. So this experiment failed and I did not find anything better than writing 
[my own native COM-client](https://github.com/the-deniss/Vulnerability-Disclosures/blob/bc776eb477abec259affaf2624322c189d36d9bc/CVE-2021-45335 %26 CVE-2021-45336 %26 CVE-2021-45337/SandboxScheduleSystemAmPplProcessExploit/SandboxScheduleSystemAmPplProcessExploit.cpp#L118) 
to call `SchRpcRegisterTask` under an impersonated restricted token.

And it worked! Using the [TaskScheduler COM API](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-2-0-interfaces) from the restricted context of the 
sandboxed `aswEngSrv.exe` you can register any task which will then be executed in the SYSTEM context without any restrictions.

If you look at the code why `TaskScheduler` allows you to do this trick you can see the following checks:

![IDA listing isPrivilegedAccount]({{ site.url }}/assets/images/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl/ida_listing_isprivilegedaccount.png)

And if `isPrivilegedAccount == TRUE` then the `TaskScheduler` allows you to register and run almost any task with any principal regardless of the caller's 
current token. Inside `User::IsLocalSystem` function there is just a check for user in the token and if it is equal to `WinLocalSystemSid` then the function returns `TRUE`. 
So it is clear why the described approach with registering a task from the context of restricted `aswEngSrv.exe` works and allows you to escape the sandbox.

Btw [James Forshaw](https://twitter.com/tiraniddo) published two posts about `TaskScheduler` features 
([here](https://www.tiraniddo.dev/2019/09/the-art-of-becoming-trustedinstaller.html) and [here](https://www.tiraniddo.dev/2021/06/a-little-more-on-task-schedulers.html)) 
where the similar idea and the same `TaskScheduler`'s code are exploited.

> NOTE: A month after I discovered this vulnerability James Forshaw wrote the article 
> ["Sharing a Logon Session a Little Too Much"](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html) which describes another interesting way to 
> escape this type of sandbox.

# 0x03: Manual PPL'ing of a process wsc_proxy.exe (CVE-2021-45337)

When researching antiviruses,you often encounter the problem of debugging and obtaining information about product processes. The reason for this is that often antiviruses 
make their processes anti-malware protected. For it AV vendors use 
[Protected Process Light](https://www.crowdstrike.com/blog/evolution-protected-processes-part-1-pass-hash-mitigations-windows-81/) (PPL) concept and set the security level 
of their processes to the [Antimalware level](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-) (AmPPL). Because of this, by design, 
a malicious program even with Administrator rights cannot influence – terminate process (there are [workarounds](https://bugs.chromium.org/p/project-zero/issues/detail?id=997)), 
inject its own code – on AV processes. But the downside of this feature is that security researchers cannot debug the code of interest, instrument it or view the process 
configuration.

Of cource a kernel debugger can be overcomethese difficulties. For example [Tavis Ormandi](https://twitter.com/taviso) [patched](https://github.com/taviso/avscript#protected-process) 
the `nt!RtlTestProtectedAccess` function. This will allow you to interact with securable objects, such as opening a process with 
[`OpenProcess`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) or a thread with 
[`OpentThread`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread) but will not allow you to load unsigned module from 
disk into the process.

> NOTE: There are also approaches like [PPLKiller](https://github.com/Mattiwatti/PPLKiller) with installing a driver that modifies `EPROCESS` kernel structures and resets 
> protection but this is too invasive for me.

And although the method described above certainly has its advantages, such as complete transparency for the product, I often reset the security by modifying the services 
config which is set by the installer at the stage of installing the product. If you carefully read the 
[documentation](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-#starting-the-service-as-protected) on how to start AmPPL 
processes you can see that at the service installation stage you need to call 
[`ChangeServiceConfig2`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w) with the handle of the configured service, 
`SERVICE_CONFIG_LAUNCH_PROTECTED` level and a pointer to the 
[`SERVICE_LAUNCH_PROTECTED_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_launch_protected_info) structure, the "protection type" member 
of which should be set to the value `SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`.

Intercepting and canceling the call to the `ChangeServiceConfig2` function with the specified parameters on the installer side seems problematic since you don’t know in 
advance from which process the protection of AV services is set. Therefore knowing that `ChangeServiceConfig2` under the hood is just an RPC client of the 
[`Service Control Manager (SCM) interface`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f), and accordingly 
each call to `ChangeServiceConfig2` from any process continues in RPC-method
[`RChangeServiceConfig2W`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/f655d914-b624-4ed8-b55b-463f17253707) of process `services.exe`, I decided 
to set a conditional breakpoint on `RChangeServiceConfig2W` and cancel on the fly attempts to do the service AmPPL.

Interestingly, there is no format in the [documentation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/42257303-29d2-4ea6-b4d2-8d5a95e4e3e0) for 
`RChangeServiceConfig2W` parameters to set the protection of a service but this format is not hard to deduce from knowing the client format and the format for other types 
of messages on the server. It turns out the following:

{% highlight c++ %}
typedef struct _SC_RPC_CONFIG_INFOW {
   DWORD dwInfoLevel; // SERVICE_CONFIG_LAUNCH_PROTECTED (12)
   [switch_is(dwInfoLevel)] union {
     [case(1)] 
       LPSERVICE_DESCRIPTIONW psd;
     ...
     [case(12)] 
       LPSERVICE_LAUNCH_PROTECTED_INFO pslpi;
   };
 } SC_RPC_CONFIG_INFOW;

typedef struct _SERVICE_LAUNCH_PROTECTED_INFO {
   DWORD dwLaunchProtected; // SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT (3)
 } SERVICE_LAUNCH_PROTECTED_INFO,
  *LPSERVICE_LAUNCH_PROTECTED_INFO;
{% endhighlight %}

And then the conditional breakpoint which replaces the installation of the AmPPL service with a NOP-call, will look like this (set in the context of `services.exe` 
after attaching to it):

```
bp /p @$proc services!RChangeServiceConfig2W ".if (poi(@rdx) == 0n12) { ed poi(@rdx + 8) 0 }; gc"
```

And it doesn't really make much difference how you disable or bypass the PPL but this approach helped me find another bug. After the full installation of the product, 
you can make sure in [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) that all AV processes are running without PPL protection:

![wsc_proxy.exe AmPPL protection after disabling PPL]({{ site.url }}/assets/images/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl/wsc_proxy_protection.png)

The processes in the picture are sorted by the "Company Name" field and, as it seems, all Avast's processes are without PPL protection. But among the processes there is 
a `wsc_proxy.exe` process (highlighted in the picture), it has AmPPL protection and is not supplied by default with the OS. So what is this process? It is also an Avast component, 
for some reason PPL protection is on it and because of this `Process Explorer` cannot read the company name of the binary from which the process is created.

At first I thought my method of not setting process PPL protection was incomplete. Well, for example, there are other SCM APIs that can be used to make a service PPL. 
But not finding any I set a hardware breakpoint on the `Protection` field of the `EPROCESS` structure of the `wsc_proxy.exe` process at its start and found that this 
field is filled from the `aswSP.sys` – the kernel self-defense module of the product:

![aswSP.sys sets protection level on process create]({{ site.url }}/assets/images/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl/on_process_create_set_protection_level.png)

The screenshot above shows that the `aswSP.sys` driver directly modifies the `EPROCESS` structure of the process and sets the `Protection` field in it as follows:
```
Protection.Type =  0n1; // PsProtectedTypeProtectedLight (0n1)
Protection.Signer = 0n3; // PsProtectedSignerAntimalware (0n3)
```

Now we realize that Avast Free Antivirus somehow not quite honestly uses the PPL infrastructure and forcibly makes its processes PPL-protected bypassing Microsoft requirements. 
And as attacker we would like to use this functionality and make our own code AmPPL. Then we can influence other AmPPL-protected processes.

To do this you need to understand when and under what conditions the code above is reachable. After reversing `aswSP.sys` I found out that the function with this code is called 
from the process creation callback handler registered with 
[`PsSetCreateProcessNotifyRoutine`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine). And in order for the driver 
to directly execute this code and make the process PPL two conditions must be met:

1. The process must be spawned from the binary file `"C:\Program Files\AVAST Software\Avast\wsc_proxy.exe"`;
2. The process must be running as "NT AUTHORITY\SYSTEM".

These requirements (if they are checked correctly) severely limit the scope of applicability of this functionality for an attacker but still allow having SYSTEM privileges to 
obtain an AmPPL protection level. This can be done by implementing the usual image hollowing of `wsc_proxy.exe` when running it as child process in the SYSTEM context. Then 
both conditions will be met and we can easily deliver our payload to the process thanks to the handle received from 
[`CreateProcess`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) with `ALL_ACCESS` rights to the created process 
and the subsequent [`WriteProcessMemory`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) with the payload. Below is the PoC of 
the proposed method:

![Obtain AmPPL protection level PoC]({{ site.url }}/assets/images/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl/wsc_get_amppl_protection_poc.png)

In the screenshot above powershell is first launched with Administrator rights. It launches a powershell instance running under "NT Authority\System" `(1)`. Next we start 
`wsc_proxy.exe` in the suspended state `(2)`. And we demonstrate that there is no PPL protection yet `(3)` but we as a parent have a handle of the child process with `AllAccess` 
rights `(4)`. Using the handle we overwrite the process memory with the necessary contents `(5)` – in this case it is an infinite loop, and continue the execution of the process. 
At this point process-creation callback implemented by `aswSP.sys` checks for the above-mentioned conditions and changes the `EPROCESS.Protection` of the process. Next we can 
verify that the process has become AmPPL-protected `(6)` and see in `Process Explorer` that the process is executing our code and consuming CPU with its infinite cycle `(7)`.

As a result due to this vulnerability we have a primitive that allows us, having SYSTEM privileges, to obtain for our process AmPPL-protection level.

By the way the `EPROCESS` structure is an opaque structure and offset to the `Protection` field is not something fixed and constant. Therefore for OSs it must be calculated. 
Avast does this by searching by signature in the exported  kernel function `PsIsProtectedProcess`:

![Find Protection offset by signature in PsIsProtectedProcess]({{ site.url }}/assets/images/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl/psisprocessprotected_signature_matching.png)

# 0x04: Exploitation chain

Building all three vulnerabilities in a chain we get the following exploitation scenario which allows you to increase privileges from Everyone to "NT AUTHORITY\SYSTEM" with the 
AmPPL protection level:

1. As standard user inject into the `aswEngSrv.exe` process;
2. Inside sandbox create a `Task Scheduler` task to run your code under the full "NT AUTHORITY\SYSTEM" account and trigger the launch;
3. Executing in the "NT AUTHORITY\SYSTEM" context start the process spawned from the binary file `"C:\Program Files\AVAST Software\Avast\wsc_proxy.exe"` with the `CREATE_SUSPENDED` 
flag, overwrite the `EntryPoint` with your own code and continue the process execution;
4. Now the code is executed in the "NT AUTHORITY\SYSTEM" context inside the AmPPL-protected `wsc_proxy.exe` process.

Below is a demo video of the exploitation (in the end the input and output of the `powercat.ps1` were slightly out of sync but I hope this does not interfere to understand the 
main idea):

<video id="SandboxScheduleSystemAmPplProcessExploitDemo" preload="none" width="740" height="480" poster="{{ site.url }}/assets/poster/SandboxScheduleSystemAmPplProcessExploit_Demo.png" controls>
    <source src="{{ site.url }}/assets/videos/SandboxScheduleSystemAmPplProcessExploit_Demo.mp4" type="video/webm">
    <p>Your browser doesn't support HTML video. Here is a <a href="{{ site.url }}/assets/videos/SandboxScheduleSystemAmPplProcessExploit_Demo.mp4">link to the video</a> instead.</p>
</video>

> Note: Recently AV has been detecting "powercat" and quarantining it. So for the demonstration purposes, the script must be added to the exclusions, and to work in real life, the 
> payload must be changed to something slightly less famous.

The full source code of the PoC can be found on my [github](https://github.com/the-deniss/Vulnerability-Disclosures/tree/main/CVE-2021-45335 %26 CVE-2021-45336 %26 CVE-2021-45337).

# 0x05: Fixes retest

After almost 3 years (now the beginning of February 2023) after discovering vulnerabilities, reporting them to the vendor and even claiming that everything was fixed, I decided to 
see how developers fixed the vulnerabilities. To do this I installed Avast Free Antivirus 22.12.6044 (build 22.12.7758.769). So let's go!

Fixing the insecure DACL of a process `aswEngSrv.exe` (CVE-2021-45335) is pretty simple: the developers explicitly set the `DefaultDACL` of the token as before but now it is a 
more strict DACL of the form `D:(A;;GA;;;BA)(A;; GA;;;SY)S:(ML;;NW;;;LW)`. The SDDL representation of DACL indicates that access is now allowed only "NT Authority\System" and 
"Administrators", while the integrity label is Low (a curious decision).

As result the token now looks like this:

![aswEngSrv.exe token after fix]({{ site.url }}/assets/images/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl/aswengsrv_token_after_fix.png)

DACL on the process corresponds to the above value from the token's `DefaultDACL` . We will not be able to inject as before so believe that the vulnerability has been fixed.

And then it’s more interesting – we move on to checking the sandbox escape (CVE-2021-45336). Back in 2020 I wrote in the report to the Avast developers that they had very 
little chance of making a good sandbox running as "NT Authority\System". But as we can see in the new version of the product the `aswEngSrv.exe` process' token has not changed 
in this regard. So how did they fix it?

The developers did not change the "NT Authority\System" user under which the `aswEngSrv.exe` process was originally executed, the set of groups and jobs too. So at first glance 
it looks like they couldn't fix the vulnerability. I manually injected the module demonstrating PoC but nothing worked as expected. It's just not clear why.

As a result of debugging the code I found out that my COM-client crashes during the initialization of the COM runtime. Previously the runtime was probably already initialized 
at the time of injection. There were quite a lot of errors and there was no desire to understand them but there was definitely an understanding that problems with the COM runtime 
could not be a sufficient mitigation from escaping the sandbox. Moreover the entire COM binding of `TaskScheduler` is client-side code implemented essentially for the convenience 
of clients. And on the server side, as we said earlier, there is a single RPC method `SchRpcRegisterTask`. Therefore I decided not to deal with errors and wrote my own [RPC-client 
of `TaskScheduler`](https://github.com/the-deniss/Vulnerability-Disclosures/tree/main/Common/TaskSchedulerRpcClient). When running the code started to fail again but when locating 
problems it turned out that the RPC runtime often uses function 
[`OpenProcessToken`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken) with the 
[`GetCurrentProcess`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocesstoken) parameter to get its own token and ends 
with `ACCESS_DENIED` since the updated `DefaulDACL` does not allow even itself to open it. I wrote a hook for such calls and replaced them with returning a pseudohandle using 
[`GetCurrentProcessToken`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocesstoken). The pseudohandle is "pseudo" because 
it does not need to be opened, so there were no more problems with access rights. And the code worked – again it turned out to register a task from the `aswEngSrv.exe` sandbox which 
runs as SYSTEM. I posted the [`CVE-2023-ASWSBX`](https://github.com/the-deniss/Vulnerability-Disclosures/tree/main/CVE-2023-ASWSBX) PoC code on my github. Surprisingly the 
developers fixed a specific implementation of the exploit but did not fix the root cause.

> NOTE: In the `aswEngSrv.exe` code I saw that different hooks are being set and perhaps that is why the original approach with COM does not work. But obviously in-process hooks 
> cannot be the solution.

As for the bug when manually modifying PPL Protection for the `wsc_proxy.exe` process, the developers have now signed the binary with the appropriate certificate and made the 
`AvastWscReporter` AmPPL service in a [documented way](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-). But if you open the `aswSP.sys` 
self-protection driver and look for functions that use the `PsIsProtectedProcess` string, you will immediately find a function that just as it was shown earlier in the screenshot 
looks for the offset of the `Protection` member in the `EPROCESS` structure. Further if you look at where this offset is used you can find a function that sets the value `0x31` in 
the `Protection` field of the process. And what is most interesting this function is reachable from the IOCTL handler:

![Path from IOCTL handler to DoProcessPPL()]({{ site.url }}/assets/images/elevation-of-privileges-from-everyone-through-avast-av-sandbox-to-system-amppl/path_from_ioct_handler_to_do_ppl.png)

So it seems that the developers have fixed this particular vulnerability but there are still execution paths in the code that can allow you to do the same thing but in a slightly 
different way (no longer hollowing or not only it).

# 0x06: Conclusions

Almost three years ago Avast released the awesome by purpose security feature – antivirus engine sandbox. Then I found 3 vulnerabilities and by connecting them in a chain I got the 
opportunity to elevate privileges from an unprivileged user to a process with the rights of "NT Authority\System" and AmPPL protection. Moreover discovered sandbox escape was a design 
problem that, by definition, cannot be fixed easily and quickly.

Then I explained to myself the "mistakes" of the solution by its novelty and hoped that over time this feature would become more mature and become an excellent investment in the 
resistance of the antivirus to bugs in the most valuable attack surface of the product.

But now I discovered that the exploitation chain was broken by fixing only one link from the chain (fortunately at least the first one 😊). The main problem is that the design of 
the sandbox has not been fixed. Which makes, sadly, all sandboxing completely useless. In addition, judging by the fact that the manual PPL'ing code is present in the driver, this 
issue may also not be completely fixed.

# 0x07: Disclosure Timeline

- 25-03-2020
Initial report sent to Avast.

- 26-03-2020
Initial response from Avast stating they’re being reviewed it.

- 23-04-2020
Avast triaged the issue reported as a valid issue and is starting work on a fix.

- 08-09-2020
Avast released patched version of product.

- 09-02-2023
This post has been published.





