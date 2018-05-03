rule Doc_Trojan_Spatch_1
{
strings:
	$a0 = { 544d5046696c65203d2022433a5c546d702e62617322 }
	$a1 = { 4d6f64756c654e616d65203d202253706f6f6c576174636822 }

condition:
	$a0 and $a1
}

        
