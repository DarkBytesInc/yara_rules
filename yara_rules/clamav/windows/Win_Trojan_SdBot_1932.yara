rule Win_Trojan_SdBot_1932
{
strings:
	$a0 = { aa117022911a673bee955ad3ac4fcd25f57910073b8a0c1b1cddae5daddda2aa0bdebe26cee6db71025eaa56575f82a2228c958589aa863a57dfaf898f1c55067a2b4e69a06979f51cb7c0daeb95b8c98518574f2dd1ca524b5c0afd1584ac }

condition:
	$a0
}

        
