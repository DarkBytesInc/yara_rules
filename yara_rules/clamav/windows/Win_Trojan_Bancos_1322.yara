rule Win_Trojan_Bancos_1322
{
strings:
	$a0 = { 3cfd7a547c6d820ddf6c8477ec2e02f2f2f8010b0c6659e630f4e0a547127d277a0bdcced99bec3e53ef81e537c3a89ef3163d2ae5167849f9ea13a609c25f60fc66ab2258fc980b34484782b067e5c69db00fbd }

condition:
	$a0
}

        
