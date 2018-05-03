rule Html_Trojan_VBSDeltree_1
{
strings:
	$a0 = { 6261742e57726974654c696e65202264656c74726565202f79202577696e6469722522 }

condition:
	$a0
}

        
