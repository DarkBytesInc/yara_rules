rule Win_Trojan_Agent_36071
{
strings:
	$a0 = { 0021d083e85e898558feffff898558fdffff85c0722231d2899534feffff01957cffffff21c281faa4080000750a29c281ea000b000001c2298518feffff3145a4018550feffff219548feffffb93d00000031ca294da0ff8528ffffff198da8feffff29 }

condition:
	$a0
}

        
