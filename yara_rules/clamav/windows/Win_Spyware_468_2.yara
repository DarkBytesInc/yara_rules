rule Win_Spyware_468_2
{
strings:
	$a0 = { 97bdcd9896bfdef296d7a6c4ddc0dd9aa19dd9e168a2321a10e6cef21e92369897bdce0de22f2620a6d7ce0de22f2684a6d7ce0de22f2690a6d7ce0de22b26a8a6d7ce9aa59ed9e17f0be1f297bff34b83c4a6f097d74e1ae0e6cef25e149b797b540a1ec1809da37cc6839be5b6a096f6f787b1c6f78ab097cdce7fd2279e9a }

condition:
	$a0
}

        
