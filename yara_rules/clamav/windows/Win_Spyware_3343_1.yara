rule Win_Spyware_3343_1
{
strings:
	$a0 = { 5261764d6f6e2e6578[0-100]4156502e50726f647563745f4e6f74696669636174 }

condition:
	$a0
}

        
