rule Win_Trojan_Mirror_1
{
strings:
	$a0 = { 535152061e5657550e1f06b435b064cd218cc03dffff7503e98800070626832e0200438cc0488ec0268b1e030083eb }

condition:
	$a0
}

        
