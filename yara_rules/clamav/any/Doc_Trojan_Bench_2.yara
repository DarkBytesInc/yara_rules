rule Doc_Trojan_Bench_2
{
strings:
	$a0 = { 4966205543617365284e5f4964656e7469667929203d20224d4143524f4e414d45203d2042454e434822205468656e204e545f496e7374616c6c6564203d2054727565 }

condition:
	$a0
}

        