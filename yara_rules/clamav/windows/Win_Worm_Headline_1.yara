rule Win_Worm_Headline_1
{
strings:
	$a0 = { 310001010800484541444c494e450005a005c0125712df0212010025010000029001407e05000f506f73746572426f }
	$a1 = { 3c4c73666955154624cc632031e54f232c173d09ce0d7541de28e1c45d4de873daada88da2986467e700f1c1e87a9c1f6cfe3588b0c72dc30c9db9c29c7f9f4fd6b7ccf12b2497205b8da07056450dee47247079ebd3af7c }

condition:
	$a0 and $a1
}

        