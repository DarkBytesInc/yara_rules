rule Win_Trojan_Hupigon_868
{
strings:
	$a0 = { 3f20388dec5b67c23f2a029a01aafaa4034c6e0888f838e7b19b1c8c05eaef523c0a14e4052ce7a035b2153c6d68f767dca30a4cbd07c0ebe76429ab7666465a42d2fbeff9aa0cc88d0c6e7bd38e11f208d015e607143fbd07e749030d6151 }

condition:
	$a0
}

        
