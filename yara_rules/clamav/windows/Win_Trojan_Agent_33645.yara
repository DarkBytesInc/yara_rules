rule Win_Trojan_Agent_33645
{
strings:
	$a0 = { 643be005092b98aa4b9004fcc86222155bc8d1b7f080d753039f06544a32492c655a1810b44d5d2ae26656e04b9a5a32900fb7c016ca6cbccac403b6adbc8450c411e9878c01c016b9000f9e2344b681380bb20376f28f38e68935ffbd1c9f3c2e694a389fa16681c1 }

condition:
	$a0
}

        