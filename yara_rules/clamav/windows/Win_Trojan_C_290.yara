rule Win_Trojan_C_290
{
strings:
	$a0 = { 4b656669277320484c4c5020436f6e737472756374696f6e204b6974205b4b48434b5d }

condition:
	$a0
}

        
