rule Win_Trojan_Bancos_949
{
strings:
	$a0 = { 193e10140df7151f6aea2f00401d025fddb1b1ca756787de2abc51fcba07a42f9faee36237ddf996f11c8b146470efc062bea2497855a0c6e62d850e3deb36b93fb5429a97bd67d0ea662425b96216775681 }

condition:
	$a0
}

        
