rule Win_Trojan_Agent_35559
{
strings:
	$a0 = { e900000000669668dd22f6c09986f464a13000000053f6d28b400c8d9375993d369ce9a45107 }

condition:
	$a0
}

        
