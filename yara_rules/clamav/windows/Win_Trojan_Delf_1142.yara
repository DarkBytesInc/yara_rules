rule Win_Trojan_Delf_1142
{
strings:
	$a0 = { 8945f06a048d45f0506a046a0068984f40008b45ec50e8d0edffffc745f0010000006a048d45f0506a046a0068a84f40008b45ec50e8b1edffff }

condition:
	$a0
}

        
