rule Win_Trojan_R_1
{
strings:
	$a0 = { 69662066636f64655b372c395d213d2250617261646f786f6e22207468656e[0-20]66636f64653d6d79636f64652b31332e6368722b31302e6368722b66636f6465 }

condition:
	$a0
}

        