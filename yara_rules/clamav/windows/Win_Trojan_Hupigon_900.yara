rule Win_Trojan_Hupigon_900
{
strings:
	$a0 = { df5eb5d88ccbbcba99a92cb2f1228b750ed437fca0a2711ff0a5f0e2ed80fa8422515bcb40a6166c1656da3b654daab1d5fe1040255279058376b8e2057436ae6e07d1ed30a4f7aebc815d75f7da193b9aba246e8c9eedfa1eb54b5fc79e0a }

condition:
	$a0
}

        
