rule Win_Spyware_Banker_2634
{
strings:
	$a0 = { 43e01b2f7ff52ae92112f4237efce33f61c478fa5899eef8236db9d067b65db379529007f862ddb703e65c49b77a4e0cb0a115e46582e9a4cd8dd0e2458eea4e499170d9b6b9994f8a2ef01bd1b513fe112932fa17debe945cb1fedb554c4f6dbb29 }

condition:
	$a0
}

        
