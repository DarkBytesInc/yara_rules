rule Win_Trojan_VGEN_699
{
strings:
	$a0 = { e800008bf436812c0400368b2c83c4021e0646b8e8030519f6ba4559cd210bf6744a8cd8488ed8b05a38060000753d }

condition:
	$a0
}

        
