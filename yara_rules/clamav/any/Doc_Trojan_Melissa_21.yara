rule Doc_Trojan_Melissa_21
{
strings:
	$a0 = { 46696c6524203d20436872242841736328436872242841736328436872242841736328436872242841202b203229292929292929202b20466e616d6524202b20436872242831303029 }
	$a1 = { 4966204e6f74496e4e54203d2054727565204f72204e6f74496e4144203d2054727565205468656e20446f626a2e5642436f6d706f6e656e74732e496d706f7274202846696c652429 }

condition:
	$a0 and $a1
}

        