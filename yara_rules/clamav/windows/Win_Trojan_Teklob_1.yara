rule Win_Trojan_Teklob_1
{
strings:
	$a0 = { 6a626f74[0-29]6c5b31313832375d[0-7]785b31393732315d[0-28]3a6972632e756e6465726e65742e6f7267 }

condition:
	$a0
}

        
