rule Win_Trojan_VGEN_403
{
strings:
	$a0 = { 50058db66a02bf000157a5a5a5b8a230cd213d0100743db82135cd218c866802899e66028cc8488ec0a10200bb2800 }

condition:
	$a0
}

        
