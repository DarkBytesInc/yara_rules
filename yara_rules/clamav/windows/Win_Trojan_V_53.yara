rule Win_Trojan_V_53
{
strings:
	$a0 = { 21be04008ede80fc1ec54408720ab413cd2f1e52cd2f581fbff800ab8cd8ab8edec54440ab3d21018cd8ab06577507d1e6b90001f3a70e1f744ab452cd }

condition:
	$a0
}

        
