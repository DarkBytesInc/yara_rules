rule Win_Trojan_Mybot_7955
{
strings:
	$a0 = { c03b8ea40206d7f8c18074e38b259d6535ecebffac8c52b0afd96f737bfce64b6a6d62b81a5fcdfec73f3fd77b25dbd3aaf3357d04eb5eef7412ad62c33fd46fbf94b57bd678831e591812c59b1d1d0e61dbd70f247c024b34333d93bfece7609f680b91578461b8b439127a36ea2b98c3beffb2078231632a15dd04eee5c6d389891150 }

condition:
	$a0
}

        