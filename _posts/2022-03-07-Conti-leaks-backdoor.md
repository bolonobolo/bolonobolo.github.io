---
layout: single
title: Conti Leaks - backdoor and frontend
date: 2022-03-08
classes: wide
header:
  teaser: /assets/images/Conti/leaks.jpeg
tags:
  - Ransomware
  - Windows
  - Conti
  - Leaks
--- 
![](/assets/images/Conti/leaks.jpeg)<br>

## Introduction
The 27 of February 2022 after the official declaration of Conti ransomware group to supports Russia in the conflict against Ukraine and to threatens every entity that would hit Russia IT infrastructures, a selfdeclarated Ukrainian operator of Conti, deserted and started to leaks chat logs and internal tools. They started publish files on Anonfiles and in the meantime they opened a [Twitter account](https://twitter.com/ContiLeaks).


Me and my collegue [Mayank](https://twitter.com/_mostwanted002_) started poke around the data leaked and published on [VX-Udenrground](https://share.vx-underground.org/Conti/) website and we found a lot of chat logs and some internal tools. There are a lot of good analysis on the chat logs, so we decided to move on the internal tools.

The first thing we saw was the Conti locker, containing both decryptor and encryptor in a password protected zip file. The password was added to avoid bad uses of the encryptor executable. 
Next thing we saw was a file called ```backdoor.js.zip``` that makes us more courious. We decided to apply the "dividi et impera" philosphy, Mayank decided to analyzes the Conti Locker and me the backdoor. [Here](https://mostwanted002.cf/post/conti-locker/) you can find the work of Mayank about his analysis.

## Conti Operator infrastructure
### The Git repository

Thanks to the initial work of [Emilio Gonzales](https://twitter.com/res260) with his [tweet](https://twitter.com/res260/status/1498476237613850628) we know that the zip file contains a git repository, so first thing is to rename the folder to ```.git```, than run  ```git init``` and ```git reset``` to retrieve the contents.

![](/assets/images/Conti/1st.png)

Then move on the content of the FETCH_HEAD file, where we find that there are three branches: ```master```, ```new_http_connections``` and ```HTTP```.

![](/assets/images/Conti/2nd.png)

Looking at the git config file we find the link and probably the owner of the repository

![](/assets/images/Conti/3rd.png)

The main repo site could be retrieved in the git folder’s config file and point to ```hxxps://gitlab-ci-token:UaA2b97vzyyEhqtgjJCT@179.]43.]147.]243/steller/backdoor.]js.]git``` that redirect to ```hxxps://179.]43.]147.]243/steller/backdoor.]js.]git```
But once connected we receive an SSL certificate error 

![](/assets/images/Conti/4th.png)

### Backdoor.js
The backdoor.js script include some others js script that implement some functionality like logging and Windows commands execution

![](/assets/images/Conti/5th.png)

Looking at the code it seems the backdoor is a possible entry point for Conti operators, it could be used for:
* Info gathering included Locale and LANG recognition
* Uploading files
* Downloading file for data exfiltration
* Command execution through javascript native dll 

The operations are controlled using bot machines, the commands are obfuscated with MD5/XOR where the victim ID is the key, then the commands are sent to the backdoor using HTTP GET and POST requests. The results of the commands and the files exfiltrated are sent to the bot machines that are controlled by the “admin” of the operation.
In the JS comments there are some instructions for these “admin” included caching the files that come from the bot. Is not clear the why of these instructions.
The backdoor is compiled using python2 and preprocess:
```python2 preprocess\build\scripts-2.7\preprocess -o backdoor.build.js -D DEBUG=1 backdoor.js```
The victim ID is built using some information collected on the victim machine

![](/assets/images/Conti/6th.png)

Then the ID is used to identify the bot that’s serving the ransomware campaign against it.

![](/assets/images/Conti/7th.png)

Looking at the code it seems the ID is built using these data:
* SwindirDC - Data of creation of windir
* SPC - Computer name
* Swindirsys32DC - Data of creation of system32 directory
* SWorkgroup - the WORKGROUP name

Then the var  Smain is valued using the collected data:
```Smain = (SwindirDC + '.' + SPC + '.' + Swindirsys32DC + '.' + SWorkgroup);```
Then the Smain is hashed by MD5 algorithm:
```var SMD5Hash = MD5Hash(Smain);```

### Language check
The LANG/LOCALE check is used probably to avoid attacks against russian and friends targets. The codes used  as a hexadecimal value and translated in the comments are the ISO country codes. The nations are listed below:

|ISO| Nation       |
|---|--------------| 
|AZ | AZERBAIJAN   |
|AM | ARMENIA      |
|BY | BELARUS      |
|KZ | KAZAKHSTAN   |
|KG | KYRGYZSTAN   |
|RO | ROMANIA      |
|TJ | TAJIKISTAN   |
|UZ | UZBEKISTAN   |
|GE | GEORGIA      |
|UA | UKRAINE      |
|TM | TURKMENISTAN |

Of course they are defined using a javascript dictionary so they can be changed, if necessary. 
The function CheckLocale() is not called anywhere in the script but is present so we can desume Conti developers are asked to implement some sort of check about targets position, to avoid hitting friendly nations depending on geopolitical situation during the time.

![](/assets/images/Conti/8th.png)

![](/assets/images/Conti/9th.png)

![](/assets/images/Conti/10th.png)

![](/assets/images/Conti/11th.png)

### Connection function
The remote client connection function allows the attacker to send GET and POST commands, previously obfuscated using MD5 and XOR encoding to bypass WAF, IDS and IPS appliances. 

![](/assets/images/Conti/12th.png)

It seems also that the interactions from the attacker to the victim are controlled by a frontend or C&C (see the frontend chapter for details) where the operator can login and find the list of victims identified by bot ID.
Some IPs are hardcoded inside the script and used for tests, they are called “Testbot”.
It seems that the bots are instructed to enter a loop since connections, command executions or results are completed.
There are also some instructions implemented to obfuscate the IPs of the C&C in the logs, using the same MD5 function previously mentioned.

### Utils.js

Define the commands that could be launched with native dll from javascript

![](/assets/images/Conti/13th.png)

### Commands.js
Defines the type of commands that could be launched on the victim machine 

![](/assets/images/Conti/14th.png)

### Log.js
Allows to log everything in a file with path c:\temp\backdoor.js.log

![](/assets/images/Conti/15th.png)

### Http.js
This file set the HTTP metadata like User agent and connection parameters

![](/assets/images/Conti/16th.png)


## Frontend
The fun fact is that we also retrieved the frontend files leaked by the former operator and opening the 7zip archives we can find 3 directory, the first one contains 33 web pages, every page contains 20 victims sorted by domain, the second one contains the same list of victims sorted by comments and the third contains some pdf with screenshots of the console operating against their victims.
The 2 identical folders contain html file and subfolder where we can find all the necessary files to make the frontend almost usable, they are css and javascript files.

### Main page
Opening the file 1.html we land on the Operator frontend

![](/assets/images/Conti/17th.png)

Where we can recognize immediately in the middle of the page the lists of the victims that probably are running the backdoor.js.

### Operator menu
On the left panel, there is the operator menu

![](/assets/images/Conti/18th.png)

### Victim session
We are able to partially navigate only the Bot page, the other links are broken because they are pointing to a dead onion site
hxxps://x6rciduomtjt25xigz7onkgxmusuwwuxqvidjkcramwg3lb5vvpsm7ad[.]onion

![](/assets/images/Conti/19th.png)

But in the meantime we can retrieve juicy information on that page, first of all we can see the column headers that help us understand the meaning of the data.

![](/assets/images/Conti/20th.png)

The columns are (from left to right):
* ID
* Bot
* OS (32 or 64 bit)
* Group (not clear what it means)
* Country
* IP
* Domain
* Hostname
* First activity (of the backdoor connection)
* Last activity (of the backdoor connection)
* Status (of the backdoor connection)
* Priority (from 1 to 5 stars)
* Comments (probably inserted by the operators)
* Actions

![](/assets/images/Conti/21th.png)

The + symbols should reveals the details off the single victim but we are unable to click on it but looking at the screenshot we can find what the details are

![](/assets/images/Conti/22th.png)
![](/assets/images/Conti/23th.png)

As we saw before, the Locale value is important for some sort of actions.

### Command builder
Just under the banner we have the command builder that allows the operator to make actions against the victim once selected form the list.
The operation available are:

![](/assets/images/Conti/24th.png)
![](/assets/images/Conti/25th.png)
![](/assets/images/Conti/26th.png)

The list is very similar to the TCmd() list of the backdoor.js file

![](/assets/images/Conti/27th.png)

Some commands are missing, so that suggests we are looking at an old version or a prototype of the backdoor.js file. Looking at the html code we found that the operations are commented so we can retrieve some informations:

![](/assets/images/Conti/28th.png)

In particular the Get_systeminfo operation is commented like this “is needed to obtain the information about the system where the bot resides”.
Also the script.js file contains the values of the choices taken by the operator and passed to the onion site using a GET call.

![](/assets/images/Conti/29th.png)

We can deduce then 2 things: 
* “the bot” means the backdoor.js file implanted in the victim machine 
* The onion site is connected directly to the victim machine using the backdoor.js file

The techniques used to run commands are not new but still interesting:

![](/assets/images/Conti/30th.png)

For the exe section the operator can use Process Hollowing, Process Doppelganging or the classic CreateProcess.
For the dll the operator can choose to run dll using native Windows OS commands or the injection method, in this last case only the Process Hollowing is available.

![](/assets/images/Conti/31th.png)

For the Powershell and Bat session the operator can chooses the run type

![](/assets/images/Conti/32th.png)

We have no informations on the Run Shellcode mode so it's not clear how it works 

It seems the console also allows downloading files but it isn’t clear if it's used for the data leakage of the victim files.
The exe, dll, powershell and bat attack sessions accept custom parameters and allow the attacker to choose to use a file called fake.exe. We don’t know what the file is but the html page contains what they seem the metadata of the file

![](/assets/images/Conti/33th.png)

* Name:fake.exe
* Size:3584
* Uploaded:2021-11-02 12:20:44
* By user: botadmin
* MD5 Hash:7c6187a71902254704866d5db8448ba0

We have squized all the informations from the leaked data about the Conti Operator System, but of course we are humans so we can do mistake or missing something. 
We invite you to ping us in case you find something new on that leaks.

## IOCs

```
backdoor.js
84BC041EAAF565C53619A37FB62590924A110D5365A6875BA0270D4BAA2F2130

http.js
168B489131DFDD67B5C8749B67C32746D6292B6929D1A33D4D2B4D6BDF2A96E6

utils.js
93B6A67AA20BE9068B264FF226982425F0ACBA722C68EE00D102FB9C80523EDB

commands.js
27C8675F597F4D86189A2FCE978C60834E1B9CCAC0E41D213FC5D108D41D5EAB

log.js
3254DF45C49831A7A565303865AB93EA47E5019D1A3FD0FC987A79C5CF23043A
```

## Conclusion
According with [the DFIR Report](https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/) it seems to be a conection about Bazaar Loader and Conti group and looking at the backdoor file it seems true. I tried to understand how the Conti group Operator System works:

![](/assets/images/Conti/Conti_diagram.png)


