rule Win_Spyware_Banker_219
{
strings:
	$a0 = { a6353e9cfc19ee8ef128486f9cac7c1ca19552370d086d089a2bde840175e79a8d9a48a58076abcc5aeaabfc93576e8d33a3e6d588f9adc9b484a2e8e49cb2fa072ea37b5eb160575a394f6cf18da75b161c1d9885ed2c9846e43808dedd02e8c1f48922cbb6fe96ad53c0036bdb503d }

condition:
	$a0
}

        
