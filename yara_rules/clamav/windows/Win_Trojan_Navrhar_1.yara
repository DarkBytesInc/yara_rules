rule Win_Trojan_Navrhar_1
{
strings:
	$a0 = { 4000a3cd224000b800000000b900010000ba06234000e84303000066813d062340004c450f }

condition:
	$a0
}

        
