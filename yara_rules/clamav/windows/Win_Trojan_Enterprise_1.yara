rule Win_Trojan_Enterprise_1
{
strings:
	$a0 = { 454e54455250524953452032e800005d81ed1101b80135cd212e891e17022e8c061902badc0103d5b80125cd21b8 }

condition:
	$a0
}

        
