rule Win_Trojan_C_7
{
strings:
	$a0 = { fa01047511b81505b500ba00008ec2bb0000cd13cd20e9a4004869212049276d20436173706572 }

condition:
	$a0
}

        
