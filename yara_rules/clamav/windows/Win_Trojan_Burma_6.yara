rule Win_Trojan_Burma_6
{
strings:
	$a0 = { faba455993cd16c35053515256571654b800b88ec0c7066f020c00c7066702d000a16702a36902c7066b023900c7 }

condition:
	$a0
}

        
