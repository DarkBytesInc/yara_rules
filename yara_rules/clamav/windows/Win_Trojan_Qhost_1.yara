rule Win_Trojan_Qhost_1
{
strings:
	$a0 = { 33322e646c6c000000003132372e302e302e33206e2d676c782e732d72656469726563742e636f6d0d }

condition:
	$a0
}

        
