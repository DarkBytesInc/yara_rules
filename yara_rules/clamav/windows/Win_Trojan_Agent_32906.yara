rule Win_Trojan_Agent_32906
{
strings:
	$a0 = { 3adfdb663a2153ae8cb436ceaaf3e6b55d8c22f8c7c401dd29fa911862fb3389276dc02be6eb47debc374d43f77f2f5278a04b792ba83cadb5962f2a321d522844ab78df4c365eaec8cca5e407ac8f921e095e7856 }

condition:
	$a0
}

        
