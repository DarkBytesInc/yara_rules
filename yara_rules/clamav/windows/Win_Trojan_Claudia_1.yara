rule Win_Trojan_Claudia_1
{
strings:
	$a0 = { bb1d00b0922e300743f6d881fb332276f47a6e92331383a36f8c68796c02872a3dd1a3b3ef693ddd1b9187306e2a6f68d4d7375f4f26445f4f13975e }

condition:
	$a0
}

        
