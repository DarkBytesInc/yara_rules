rule Win_Trojan_Vundo_417
{
strings:
	$a0 = { 50eb1b42e80edeff46e82384ff46ffd3e805e4ff4649ffd4ffd3ffd56a9ce8c702000087f6d3e080e8ced2c808c06681f08b5458e8e9fcffff86d290eb21cc5a41ffd4e9ce8f00006aadc9c9ffd56a1ee855a5ff46ffd2c9e93e9500006a8fe9d6f9ffff }

condition:
	$a0
}

        
