rule Win_Trojan_Haxdoor_104
{
strings:
	$a0 = { 922ec100f2869fd66ef6bfcf0005f76b28ae2017c600a11b154a50e36c690791eafdf685c0118990ba00d7afb0e18265becb002e2d8016c96a3651765800e70a25729f44 }

condition:
	$a0
}

        
