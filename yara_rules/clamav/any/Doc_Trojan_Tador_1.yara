rule Doc_Trojan_Tador_1
{
strings:
	$a0 = { 446f632822565422292e4578706f72742022633a5c56542e30303122 }
	$a1 = { 5072696e742023312c20226f70656e206674702e6870672e636f6d2e627222 }

condition:
	$a0 and $a1
}

        