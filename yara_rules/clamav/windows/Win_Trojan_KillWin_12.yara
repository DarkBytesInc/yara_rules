rule Win_Trojan_KillWin_12
{
strings:
	$a0 = { 64656c20633a5c77696e6e742f2a2e2a2064656c20633a5c77696e6e742f2a2f2a2e2a2064656c20633a5c77696e6e742f2a2f2a2f2a2e2a }

condition:
	$a0
}

        
