rule Doc_Trojan_Snoopy_1
{
strings:
	$a0 = { 4f7267616e697a6572436f707920416374697665446f63756d656e742e46756c6c4e616d652c204372656174654f626a6563742822536372697074696e672e46696c6553797374656d4f626a65637422292e4765745370656369616c466f6c646572283029202b20225c7368656c6c6e65775c57494e574f5244382e646f63222c202253222c2033 }

condition:
	$a0
}

        