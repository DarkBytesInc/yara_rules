rule Win_Trojan_Grab_3
{
strings:
	$a0 = { fd079a00009b079ae91429045589e581ec0002b80000ba530152509ad705290409c07d08bf77000e57e847f7b8 }

condition:
	$a0
}

        
