rule Win_Trojan_DST_4
{
strings:
	$a0 = { 33c08ed839060200581f74711e51811e020000088b3e02008ec7bf000183ee03b9a801f3a41e508cd8488ed883 }

condition:
	$a0
}

        
