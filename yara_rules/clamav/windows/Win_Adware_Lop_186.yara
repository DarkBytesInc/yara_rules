rule Win_Adware_Lop_186
{
strings:
	$a0 = { 84c90a66121495086c67adefc37dd4de30868909af37b81e11630420fa6a50ba4f8bbba1b719158c4a1fcb01718543789b4a94eb4d3391db6b985713 }

condition:
	$a0
}

        
