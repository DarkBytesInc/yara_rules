rule Win_Trojan_Autorun_420
{
strings:
	$a0 = { 2e77726974656c696e65225b6175746f72756e5d22 }
	$a1 = { 2e77726974656c696e65227368656c6c657865637574653d777363726970742e657865 }

condition:
	$a0 and $a1
}

        