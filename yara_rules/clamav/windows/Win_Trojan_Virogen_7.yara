rule Win_Trojan_Virogen_7
{
strings:
	$a0 = { e9100090bf1b01909090909083c70090e8ca04e98101000000000000434f4d4d414e442e434f4d9090e9000000 }

condition:
	$a0
}

        
