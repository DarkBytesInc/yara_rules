rule Win_Trojan_Coca_1
{
strings:
	$a0 = { 505351525657061e8cc88ed8c4062902a37e018c068001b41abaa901cd21b82a2ea38201354f56a3840132e4a38601 }

condition:
	$a0
}

        
