rule Win_Trojan_Philis_103
{
strings:
	$a0 = { 56e804000000e8e9eb0e5eeb02e9e883c602eb01e856c3e95e6056e804000000e8e9eb0e5eeb02e9e883c602eb01e856c3e95ee800000000565e565290 }

condition:
	$a0
}

        
