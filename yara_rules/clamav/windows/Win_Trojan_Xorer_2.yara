rule Win_Trojan_Xorer_2
{
strings:
	$a0 = { 83c9ffbfa490400033c0f2aef7d12bf98bc18bf7c1e902bf90a54000f3a58bc833c083e103f3a483c9ffbfa0904000f2aef7d12bf98bd18bf783c9ffbf90a54000f2ae8bca4fc1e902f3a58bca83e103f3a483c9ffbf9c904000f2aef7d12bf98bf78bd1bf90a5400083c9fff2ae }

condition:
	$a0
}

        
