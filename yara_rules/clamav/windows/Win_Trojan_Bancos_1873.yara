rule Win_Trojan_Bancos_1873
{
strings:
	$a0 = { 4cdf095ae95a826ea2341b969e485ee5f175558159862adb560426e7ebe89a15c60a7bb0c524c8e61992361e46de41f749834796cd8bee999cc4aae8fe2c88045aea9a7b3d25 }

condition:
	$a0
}

        
