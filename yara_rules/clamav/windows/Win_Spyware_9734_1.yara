rule Win_Spyware_9734_1
{
strings:
	$a0 = { 558becb90a0000006a006a004975f9535657b8fc461413e8d8efffff33c05568834a141364ff306489209090 }

condition:
	$a0
}

        
