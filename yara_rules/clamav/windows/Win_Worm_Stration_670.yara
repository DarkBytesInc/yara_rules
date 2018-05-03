rule Win_Worm_Stration_670
{
strings:
	$a0 = { e50f007e3a2f2f045f5103c551b4c6d8fdb7ffffdfd5d8c3b4cdc2e8e2e5f4fca2a3cdfffe07e1f0f5bff4e9f491ffffdbbf592d62657e2d3d106a2531342130752620363630262633203939ffff }

condition:
	$a0
}

        
