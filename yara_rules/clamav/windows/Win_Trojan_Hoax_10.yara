rule Win_Trojan_Hoax_10
{
strings:
	$a0 = { 54686973206c6574746572206973206265696e672073656e742076696120456d61696c20616e64206e6576657220656e647320756e74696c20796f752064656c65746520616c6c2074686520636f756e746572666569742050756d6120676f6f6473 }

condition:
	$a0
}

        