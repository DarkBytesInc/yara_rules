rule Win_Trojan_SdBot_2357
{
strings:
	$a0 = { 77c07072696e7466c7144c4fe044455220dd063cf6e0543d686528703e376475b8af9b42e3797f20df530f2573ef6323756c64ffcdd0f562aa38876d61e21ebf3877de6b5e793fbe6d36632e20636b0b6272f675d568513e6fb5642c19a21e755a43f090c198700464d209e5522b18670247faf16741effdabf531234d6f43c16cf5ef1b7246eb411e274c6ffd74a453ff3db3a3b435 }

condition:
	$a0
}

        