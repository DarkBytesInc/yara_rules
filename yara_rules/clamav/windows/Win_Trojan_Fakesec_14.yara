rule Win_Trojan_Fakesec_14
{
strings:
	$a0 = { 6800a04600b8??30400066832000ff30588bc8f9143b03088b411cc1c80c2c002c5059720990909090e9 }

condition:
	$a0
}

        
