rule Win_Trojan_Nr_1
{
strings:
	$a0 = { cd213d724e7503e906011efa8cc8488ec026832e030014268b160100260316030033c98ec126a18400268b1e86 }

condition:
	$a0
}

        
