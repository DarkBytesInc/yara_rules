rule Win_Trojan_Delf_1036
{
strings:
	$a0 = { eeff04adfae2dc63ed5bc21d2093cbbe52dcee93c6b7f6e1b51e775e3562a307cd01ef8e7902513970e4d6be2c2ad75280947f1765ff781e1e892765d04e68ce8655e73ffc9d6d578c63d459659055cfc67e95ce3818c2ff00 }

condition:
	$a0
}

        
