rule Win_Trojan_Bancos_876
{
strings:
	$a0 = { 8072021aa0a92f98fd7a6190f8ce0ff4335d233af2a0352dd4e45fc81b715f010619710c7053cac22932dc92b794718cbf027c949687233fd9eb833c7a7e17aec0 }

condition:
	$a0
}

        
