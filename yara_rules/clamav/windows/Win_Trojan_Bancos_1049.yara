rule Win_Trojan_Bancos_1049
{
strings:
	$a0 = { 76b1ed4ba364b18521253c85e90fe6d80c5db3ebb2c4b9244d783468f2f94b5b3179180120797fe33c42283d648ab79cca22c634be80b693107b60519c05c8ed }

condition:
	$a0
}

        
