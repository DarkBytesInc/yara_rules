rule Win_Trojan_Copyme_3
{
strings:
	$a0 = { 66696e642022636f70796d65223c25303e2572616e646f6d252e626174[0-1]676f746f20636f70796d65 }

condition:
	$a0
}

        
