rule Win_Trojan_N_49
{
strings:
	$a0 = { ff579de82900558bec2e813e8b0100037217817e0400037314508b46022ea38b018b46042ea38d0158806607fe5dcf }

condition:
	$a0
}

        
