rule Win_Trojan_Agent_35085
{
strings:
	$a0 = { 7279666f73637774736d6d7761636c6361746e7873686f6f676864756974 }

condition:
	$a0
}

        
