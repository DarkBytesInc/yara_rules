rule Win_Trojan_DeadByte_9
{
strings:
	$a0 = { b800428b1ed30233c933d2cd21b4408b1ed302b91b00ba6603cd2133c9a1db02bb0002f7e383d1008bd0b800428b1ed302cd21b4408b1ed3028b0e4904ba0001cd21b43e8b1ed302cd21b44fe9b0fe1e }

condition:
	$a0
}

        
