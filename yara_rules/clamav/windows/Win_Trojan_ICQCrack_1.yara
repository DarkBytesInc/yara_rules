rule Win_Trojan_ICQCrack_1
{
strings:
	$a0 = { bf0a0d2020204c696768744272696e676572277320637261636b20666f720a0d2020204943510a0d }

condition:
	$a0
}

        
