rule Win_Trojan_Leprosy_59
{
strings:
	$a0 = { 53bb????03de8b073384????890743b9????03ce3bd97eee }

condition:
	$a0
}

        
