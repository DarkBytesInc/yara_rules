rule Win_Trojan_Hupigon_863
{
strings:
	$a0 = { 6947928fbdc09df04ec5a7702bef3ae5b86f048d9b543be95263e5f3fab6e835f04cd410617b40c4d563ea42d68816fcd1426fa91b906d6cda1619525987fb7b8180ccdae122c97ddade51e6dcbab5a91d0966e999e8524aae41510cf0cb05 }

condition:
	$a0
}

        
