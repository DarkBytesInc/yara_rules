rule Win_Trojan_Bitem_1
{
strings:
	$a0 = { 5c72756e5c77696e646f77735f7374617274757022[0-14]5c77696e6c6f616433322e696e692e76627322 }

condition:
	$a0
}

        
