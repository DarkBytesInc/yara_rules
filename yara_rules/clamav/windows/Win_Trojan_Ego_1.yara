rule Win_Trojan_Ego_1
{
strings:
	$a0 = { d988228d21319344ea01328d4c13036004c65007d180503fcdf7aab983c81febfcb05fd25188f75dd123ed210617f023bf9b937db743dbe2b12d7a578960eee8 }

condition:
	$a0
}

        
