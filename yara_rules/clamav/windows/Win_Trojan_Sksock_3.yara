rule Win_Trojan_Sksock_3
{
strings:
	$a0 = { c5159eb1957d007b8a59a0befce777d9a39867772137b31a10271fb7f7201d33222cf2632f87812f4aaa139add796823cf2d31b8bf63211ff2d3b89297f4cf7ea5ad6aa7940af706137a734f4a8467540afe549c6067d0ea9210d17f0f52ef1564f8fe2bd0054e41d8fe7369719158e3baa15dde08c95b524bdace8e75 }

condition:
	$a0
}

        