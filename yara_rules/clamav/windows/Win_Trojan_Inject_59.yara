rule Win_Trojan_Inject_59
{
strings:
	$a0 = { b80a00000081c00000240081c0f56400f05089c389cb83c064b95850505083c06481c10008080851ff }

condition:
	$a0
}

        
