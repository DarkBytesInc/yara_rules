rule Win_Trojan_DIRII_3
{
strings:
	$a0 = { ff067904b430cd213c041bf6c6060e04ffbb6000b44acd21b452cd2126ff77fe26c51f8b40153d7000751091c64018ff8b7813c7401377048c4815c558 }

condition:
	$a0
}

        
