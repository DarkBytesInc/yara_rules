rule Win_Trojan_Voodoo_7
{
strings:
	$a0 = { 9a000088005589e5b800039a3005880081ec0003909090bfde311e57bfe0311e57bfe2311e57bfe4311e579a00006f00 }

condition:
	$a0
}

        
