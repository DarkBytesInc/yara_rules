rule Win_Trojan_Bancos_1406
{
strings:
	$a0 = { ee3390aafdda75440cf4c4ad06e499624cab239ab982507a3f9fbd7be6e97b839d2bf1154d892cb94223afd8b26754e87d0ef5d0a48c0d670463f2e49b7957c1537ced79900836a2b695b86bb28dfd8ca6bffe8eae2b808de0d72ec6 }

condition:
	$a0
}

        
