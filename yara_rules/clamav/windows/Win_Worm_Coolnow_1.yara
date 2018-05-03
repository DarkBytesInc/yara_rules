rule Win_Worm_Coolnow_1
{
strings:
	$a0 = { 3a2f2f6d7368746d6c2e646c6c2f626c616e6b2e68746d22 }
	$a1 = { 2e667269656e646c796e616d65203d20227669636e616d6522 }

condition:
	$a0 and $a1
}

        
