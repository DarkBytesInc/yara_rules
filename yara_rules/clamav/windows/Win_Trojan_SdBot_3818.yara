rule Win_Trojan_SdBot_3818
{
strings:
	$a0 = { 2268a7a356773a8c59d012ad959f75e571edfc9396c95ee1a89c8d5d103f1f372047587f2bd237fecdcbaa357ee7b2f97db9e9bc38c7bce36b897c1856dfd098b03e363997a77a475e99032ec70eadd7b8903ebdadbaa9a5730f9e2a9c3e6b01a08b }

condition:
	$a0
}

        
