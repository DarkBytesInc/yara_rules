rule Win_Spyware_51151_1
{
strings:
	$a0 = { f033f650c745f033363054ff7508c745f47261792e8975fcc745c033363053c745c46166652e }

condition:
	$a0
}

        
