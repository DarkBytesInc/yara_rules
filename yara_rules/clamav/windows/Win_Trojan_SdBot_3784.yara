rule Win_Trojan_SdBot_3784
{
strings:
	$a0 = { dd12272b889c36902475814447d5d2945255585b13e7c5676a6dd9e8c6bd7d687b2b898ce8eb1a58aa23dda9a7aa30edd3aafcbcbf36d24b0816c517d7daec65bbeae9ec72af21f5fafd01138bd311101399beccff212428b6b375333639c0fcc8ae }

condition:
	$a0
}

        
