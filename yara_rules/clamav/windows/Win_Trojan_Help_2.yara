rule Win_Trojan_Help_2
{
strings:
	$a0 = { 50b824c5ed80356a3b7e7e50b8339a6c3f356d6593c050b89a7928d23565a9493b50b8d89dd0793587c5ba7b50b87e43aae3355a85ade3506853448b3c }

condition:
	$a0
}

        
