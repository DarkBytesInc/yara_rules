rule Win_Trojan_Banbra_140
{
strings:
	$a0 = { 061189ac8738d7b98fbb3000d91c027de215ecc67273d9fb6ae3df77df345ab5f5c36cfc54c49ef8f308951a0d589039aaac7b62fc32f4129b51f58915cb5e6e8a60066d62a3687968c077da09af3863 }

condition:
	$a0
}

        
