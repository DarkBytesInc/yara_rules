rule Win_Trojan_Hipp_1
{
strings:
	$a0 = { e800005e559c50535152571e0683ee10562e813c4d5a909075262e8b840f032e898419012e8e5c02908cd82e2b8411 }

condition:
	$a0
}

        
