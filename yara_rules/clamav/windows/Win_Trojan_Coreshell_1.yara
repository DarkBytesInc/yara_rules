rule Win_Trojan_Coreshell_1
{
strings:
	$a0 = { 8b45f86a0703c733d28945e88d47015b024d0ff7f36a078a043233d2f6e98ac8[160]03c733d28945e08d47015bf7f38ad96a07025d0f8a043233d2f6eb8ad88bc75f }

condition:
	$a0
}

        
