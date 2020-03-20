---
layout: single
title: Using Pihole to fight phishing
date: 2020-03-20
classes: wide
header:
  teaser: /assets/images/shell.png
tags:
  - Phishing
  - COVID
  - DNS
  - Pihole
--- 
![](/assets/images/Various/phish.jpg)<br>

## Introduction
Due to recent events about COVID-19 some Health Centers in Europe are victims of ramsonware attacks. The first channel to spread ransomware is phishing so here are some suggestion to block surfing to phishing sites if you have clicked on the phishing link in the email.
I installed some time ago the Pihole Ad Blocking on my Raspberry Pi, to avoid the annoiyng commercials AD when surfing the net from home. But the Pihole can have more powerful applications such as adding other types of blacklist to the Pihole - and phishing site black list could be one of them.

## The chain
The chain to follow to transform your Pihole in a DNS that blocks phishing links is preatty easy:

1. download and install the Pihole; there are many guides in Internet, depending on where you want to install it [here's one for Raspberry](https://blog.cryptoaustralia.org.au/instructions-for-setting-up-pi-hole/)    
2. add the phishing list to the adlist.list of your Pihole istallation
3. update your Gravity list 
4. that's it.

As said, the first step is pretty simple - yet it's offtopic here (ping me if you are in trouble with the installation), so I'll discuss directly the second point. 

### Add phishing list
I recently found a very good project that updates a phishing blacklist every 6 hours. This list could be implemented in the Pihole to block phishing sites.
It is called [Phishing Army](https://phishing.army/) and it updates its lists directly from 3 sources:
- [Phishtank](https://www.phishtank.com/)
- [Openphis](https://openphish.com/)
- [PhishFindR](https://github.com/mitchellkrogza/Phishing.Database)  

The first thing to do is to report and vote for phishing sites, the easy way is to follow the instruction written on the amazing blog of the [CyberV19 volunteers](https://cyberv19.org.uk/2020/03/20/helping-the-fight-against-phishing/) about voting system on Phishtank.
When the link reaches a good number of votes it is marked as phishing, then it will be put in the blacklist update of Phishing Army and automatically inside your Pihole.

### Add Phishing Army blacklist to your Pihole
To add the Phishing Army black list to your Pihole simply add the list to the list file in the path  ```/etc/pihole/adlist.list``` file in your Pihole installation.
Just connect to the Pihole via ssh and type this command

```bash
# vim /etc/pihole/adlists.list
```
paste the link at the bottom of your list file, write and quit.

![](/assets/images/Various/pihole_adlists.png)<br>

Now you have to update the Gravity black list by typing the command
```bash
# pihole -g
```
![](/assets/images/Various/pihole_adlists_update.png)<br>

### Checks
Now you can check if your Pihole is blocking malicious DNS requests.
Search for a full or partial link in the Query Lists Search of the Pihole

![](/assets/images/Various/pihole_adlists_request.png)<br>
![](/assets/images/Various/pihole_adlists_request2.png)<br>

Try to surf one of the links in the results and see the DNS query blocked by the Pihole.

![](/assets/images/Various/pihole_adlists_request3.png)<br>
![](/assets/images/Various/pihole_adlists_request4.png)<br>

Well done!

### Conclusions
This is a home setting, for enteprise solutions I would suggest to install the Pihole in a docker and configure the Domain Controller to point to the Pihole as your primary DNS.