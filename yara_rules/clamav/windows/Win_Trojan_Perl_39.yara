rule Win_Trojan_Perl_39
{
strings:
	$a0 = { 7768696c6520283c2a2e626174202a2e636d64202a2e706c3e29[0-17]6d792040766963636f6465 }

condition:
	$a0
}

        
