rule Win_Trojan_Soraya_1
{
strings:
	$a0 = { 5f4d616465303036324b697373335f576176795f55726473506f7379345f4e7562736b696572356861777366617374404059474b504344555f53454355524954595f41545452494255544553404050435f573250434e405a }

condition:
	$a0
}

        