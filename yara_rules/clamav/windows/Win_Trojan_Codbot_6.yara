rule Win_Trojan_Codbot_6
{
strings:
	$a0 = { a62b9ccbcb4659f84cdc27fb9fcf6a2d1c554ace56d5c63f457eb1b9ea6741b5a4993ad660c853f71deb21b7f9bbc49b3c0a5b13f7bf8a44da7136fb9bc41f3d9be2cd57521f63a0bf8905aec91a140185f65b5be845801402ed8d68875a94fe }

condition:
	$a0
}

        
