rule Win_Spyware_Keylog_1
{
strings:
	$a0 = { 5b235b206b65796c6f67676572206c6f67207374617274205d235d[0-32]2820246c6f67202c20223c623e }

condition:
	$a0
}

        
