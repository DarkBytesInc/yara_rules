rule Win_Trojan_Crypt_189
{
strings:
	$a0 = { 6829324300e8155d0200687e684500e8fb46020096d368b8fd4200e8ce43020067936101fd13102c }

condition:
	$a0
}

        
