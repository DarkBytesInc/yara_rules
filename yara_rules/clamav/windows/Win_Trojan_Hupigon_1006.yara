rule Win_Trojan_Hupigon_1006
{
strings:
	$a0 = { c00552f43a1a652d1839b5e46b0b8eb4a8f6564900b07e5b8e50d60c6faf908dbc0a1e2dd0eca669e1afd312052d28ccb0aff0208ff50e50858cc98f6a08d4f27618eaaafbcfba72198e75e0be62ddd30822da3908d75a7bdf9ab64a }

condition:
	$a0
}

        
