rule Win_Trojan_VGEN_579
{
strings:
	$a0 = { 0e01b9f203b80000310547e2fbb430cd213c041bf6b452cd2126c51f8b40153d7000751091c64018ff8b7813c74013 }

condition:
	$a0
}

        
