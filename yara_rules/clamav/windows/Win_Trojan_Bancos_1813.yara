rule Win_Trojan_Bancos_1813
{
strings:
	$a0 = { a3b33409977d1796ec8fd2ac537e36d9f9ebb2da353a2a77677bd0d05c611296819c3e80b520f4411a594a542df947ea711e421912067905e02fbbe2d040a7ef5c5526f7abd4 }

condition:
	$a0
}

        
