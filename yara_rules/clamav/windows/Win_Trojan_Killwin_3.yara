rule Win_Trojan_Killwin_3
{
strings:
	$a0 = { ff75e868d80e45008d9544feffff8b45ece8190077dcffb544feffff68f00e45008d8548feffffba04000000e819003a248b9548feffff8d8598feffffe819001df0ba010000008d8598feffffe8190021fce81900187cc645e741bb00001000 }

condition:
	$a0
}

        
