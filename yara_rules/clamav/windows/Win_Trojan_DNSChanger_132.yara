rule Win_Trojan_DNSChanger_132
{
strings:
	$a0 = { aec2d27bd0d14c1d6aec9532eb2a6fd8ac233930d0e9603f6fe23930eb7a6a5814252630143ffd20ab2a02f3626fc53f6fb33930eb1364209e326a5aef79c605a73b7930b879c64517d52c44fa6a39b9aedeb24d1711c2449e }

condition:
	$a0
}

        
