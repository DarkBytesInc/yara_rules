rule Win_Trojan_Agent_36090
{
strings:
	$a0 = { 3762337077756e69306a6436 }
	$a1 = { 3567396c2f2f7976736b39712b393275727a64 }
	$a2 = { 79666f2f75616a6d6a746267392b342032796f75 }

condition:
	$a0 and $a1 and $a2
}

        
