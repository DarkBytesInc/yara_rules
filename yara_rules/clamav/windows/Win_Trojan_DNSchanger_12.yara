rule Win_Trojan_DNSchanger_12
{
strings:
	$a0 = { 97fa977b7a7b7b2df00e73fe8d74ffaa7b7b7bf03d63febb0f6f130b6c7b7b2b846e0b6b3b7bfebb74fecd7b7b7bf07dfebb74ffd77b7b7bf8057f7b74ffd97b7b7bf805737b74ffe37b7b7b840d6b2b846e276a3b7bfebb74fffd7b7b7bfbde7b8484847b282c11442248bbf6c67a848484137b7a7b7b88 }

condition:
	$a0
}

        
