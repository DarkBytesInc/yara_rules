rule Win_Trojan_Companion_3
{
strings:
	$a0 = { cd21891e65018c066701ba1801b425cd21b29acd2780fc4b75475653515706501e52bf6901578bf20e07acaa0ac075fa26c645fe56b4565fcd217219b4 }

condition:
	$a0
}

        
