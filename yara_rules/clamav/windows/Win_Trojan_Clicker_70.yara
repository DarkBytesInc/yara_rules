rule Win_Trojan_Clicker_70
{
strings:
	$a0 = { 3c212d2d68705f643030[0-11]25336325346425 }
	$a1 = { 2532662532322533652229[0-17]6e6f7363726970743e746f }

condition:
	$a0 and $a1
}

        
