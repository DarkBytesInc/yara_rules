rule Win_Trojan_Agent_33544
{
strings:
	$a0 = { 82c9922ea9801d988ab01111abe07e2838101e882f411e751b00474442744eb5122ea3239c17080168062c4918d525d4d29c34243d804b22810e39400ae0a10343f794007ddbeeab7e0deb82491486b9cc19832e0bc26c794bcb00c025266eb30a38d9ce1c272bfb16 }

condition:
	$a0
}

        