rule Win_Trojan_Hupigon_194
{
strings:
	$a0 = { 65ea74e4d054913036cc3cc57e024abfa179a5bfbbaa0f86daf46f62ba9b4ac4c6310743797b89680fff2314daea47b794527186306954e66513367c3cf9c5eb6ab8ac905dbf184dd35cb04f588d0b69c6b133194f9668dc569a86c277160360bd11f9518562653d0f }

condition:
	$a0
}

        