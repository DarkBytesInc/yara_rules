rule Win_Trojan_Laroux_10
{
strings:
	$a0 = { 2000400028000a010000ad000f0057494c4f572e786c7321636865636b002000400028004a004f00ffff6a00ffff6b }

condition:
	$a0
}

        
