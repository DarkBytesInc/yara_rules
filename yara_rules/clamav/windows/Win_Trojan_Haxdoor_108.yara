rule Win_Trojan_Haxdoor_108
{
strings:
	$a0 = { 1780435a00b64cc389f16013aea97f00cdadb7c7133801e99901d69bdf862193c093ad0078ea0c33b63d9a801776b114009966e44e21ec03d93cc6ab7f83a0b2de970001 }

condition:
	$a0
}

        
