rule Win_Trojan_Fula_1
{
strings:
	$a0 = { 452d425945204861524420445269564521212121210d0a2d80202739330d0a24b1c5 }

condition:
	$a0
}

        
