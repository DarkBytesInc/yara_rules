rule Win_Trojan_Mybot_6884
{
strings:
	$a0 = { c9b1da6b21f4b1962fe9ca7f92df9873e8b870ba4e34e255310ad33798e6f6ddd76cde51d52f291ee3626f9daaa9538396c0b642512225daecf024ca1e86fef571110dc2b8776e9074665b7c4c3c53393d76735e62bf146d0e8832b01ca30f594d5098680f86208207d1f06581be60a7cbe9cf12c11bcae318dfd2cdc858991db26b37ba34ca422d6312f4ee8195a6a731256a342174 }

condition:
	$a0
}

        