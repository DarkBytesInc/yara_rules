rule Win_Trojan_Nazi_7
{
strings:
	$a0 = { 9a00007f005589e5b800039a30057f0081ec0003909090bfbe301e57bfc0301e57bfc2301e57bfc4301e579a00006600 }

condition:
	$a0
}

        
