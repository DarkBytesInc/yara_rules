rule Win_Trojan_Zbot_1243
{
strings:
	$a0 = { 89ff8b442404505d55ff15f0474100508b1c2483c40483fb0075195089e05068fe0000005050ff155c40 }

condition:
	$a0
}

        
