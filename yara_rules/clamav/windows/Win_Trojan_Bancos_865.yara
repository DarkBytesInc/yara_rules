rule Win_Trojan_Bancos_865
{
strings:
	$a0 = { 4c38cfdf8f76fd8d64be788937cae221f7198b93e54f5e832b9616c4b9d54c286a61722ab5e1651ee34662a097f933d5967de3d4fee321124373294b08fd42d066 }

condition:
	$a0
}

        
