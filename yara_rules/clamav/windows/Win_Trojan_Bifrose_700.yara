rule Win_Trojan_Bifrose_700
{
strings:
	$a0 = { bdd26d4c331ccd9c2983d417319880c02dee0005e6b67930525cdc161610970072fb2bf4510b004aeb60c22ad2e93100862364b83c4170ed00293ec1ae01f87ea9007ba4 }

condition:
	$a0
}

        
