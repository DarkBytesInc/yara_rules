rule Win_Trojan_Bancos_1003
{
strings:
	$a0 = { e107310973638c08fcbd174f1d6e58ea3acec773c98c4fa03a1a6525167fd2f0272aea7ec28b94232ed3d9d697118b4673db1d769cc1c1cd3c46b21e476bf716adbebe25d9e5594d72b5530bb0920e4a1c84 }

condition:
	$a0
}

        
