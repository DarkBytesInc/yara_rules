rule Win_Trojan_7Solution_1
{
strings:
	$a0 = { e800005d1e0606b84035cd218cc0073d00f07418b42ccd2180fa077d0fb93f008ac1e67032c0e671e2f6eb4b33ff8edf813e04005e01742d8cc048832e130401 }

condition:
	$a0
}

        
