rule Win_Trojan_LdPinch_93
{
strings:
	$a0 = { 9bc1b08d61011dba61796d561ac1860b2415805658f811446566610a741707b75bbbb583b42044801d61734239397cc696db62000032306105623161fec2ddf2320b1f424372327449560068095b58b8356e3273772864cd53acc3daf6b677614e5c4768626c80b8946d8686200e6ddb1100226d3660ee546fc12049d2c5db8f6d6f0a4674700d69d45c7763785f3970c15602b62e50 }

condition:
	$a0
}

        