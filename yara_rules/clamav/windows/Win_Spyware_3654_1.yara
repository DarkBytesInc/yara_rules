rule Win_Spyware_3654_1
{
strings:
	$a0 = { 1000eb2683fe01740583fe027522a1 }
	$a1 = { 25733f613d257326733d257326753d257326703d257326[17]3d25 }

condition:
	$a0 and $a1
}

        
