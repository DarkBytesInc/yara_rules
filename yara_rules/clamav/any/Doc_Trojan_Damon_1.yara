rule Doc_Trojan_Damon_1
{
strings:
	$a0 = { 486f73742e44656c6574654c696e657320312c20486f73742e436f756e744f664c696e6573 }
	$a1 = { 73446f63756d656e742e5361766541732046696c654e616d653a3d54686973446f63756d656e742e46756c6c4e616d65 }

condition:
	$a0 and $a1
}

        