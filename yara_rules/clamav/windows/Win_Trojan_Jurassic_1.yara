rule Win_Trojan_Jurassic_1
{
strings:
	$a0 = { 902e8c069604b80312cd2f813e9f10250175208cc08ed80510002e010670042e010674042e8b2672042e8e167404 }

condition:
	$a0
}

        
