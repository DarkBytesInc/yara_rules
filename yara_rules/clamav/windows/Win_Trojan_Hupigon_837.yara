rule Win_Trojan_Hupigon_837
{
strings:
	$a0 = { f2b4bcea5edc13dd8f816da4552bd62a62db52fc0ff1ed84de0eaf47004fd6e26307212109262240cccebae7ed7a312749bc6aa27058a073f4700448ac04f0822a6b8dc15bf0ff17a08a9f7749293ac0e11ec755e863fb2e5773f1a0021bfb }

condition:
	$a0
}

        
