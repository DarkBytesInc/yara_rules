rule Win_Trojan_HookDump_1
{
strings:
	$a0 = { befefe165768ff009affff0000803e110000740b8dbefefe1657e8ecfeeb2ee8abfebfbe001e579affff0000bfbe001e578dbefefe16576a009affff00009affff0000bfbe001e579affff00008a46ffc9c20400190d0a5b49742773206120486f6f6b2044756d702066696c65 }

condition:
	$a0
}

        
