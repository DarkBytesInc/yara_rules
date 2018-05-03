rule Doc_Trojan_Cooldown_1
{
strings:
	$a0 = { 507269766174652053756220436f6f6c446f776e28486f77 }
	$a1 = { 46696e642822436f6f6c }

condition:
	$a0 and $a1
}

        
