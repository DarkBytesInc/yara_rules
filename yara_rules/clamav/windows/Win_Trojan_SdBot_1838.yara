rule Win_Trojan_SdBot_1838
{
strings:
	$a0 = { 63c7cc7a5c5d894f2b34c52a2a1ae0e8f98e1d3f8b91491bdf36323c6008484d94eb2a8ebcb4fa390d64f6aa6afe03c3c9a0679cc5481fe5ad4c923427a75b7a10c269106b14503ecf895e554fd403547f2da784696968d73bd0321401bc8637bc88c5a7 }

condition:
	$a0
}

        