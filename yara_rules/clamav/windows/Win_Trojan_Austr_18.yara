rule Win_Trojan_Austr_18
{
strings:
	$a0 = { ba0001b440cd21b8004233c933d2cd21b440b90700ba0001cd21b80242 }

condition:
	$a0
}

        