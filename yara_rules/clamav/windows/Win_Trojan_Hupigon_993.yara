rule Win_Trojan_Hupigon_993
{
strings:
	$a0 = { 915c7d35833ef24d8a4c75826a6cd0264ec8cc720bedbf45e4ce422bccd5975f45ade5100ee26a5ea52a6873888cd2babb867697de07ed4c46a5c0f7a44a2246f39e2fac13082235f4384a0abfe1df6cc2fc7a46bb2f1f7df7b125ac }

condition:
	$a0
}

        
