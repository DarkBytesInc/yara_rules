rule Win_Trojan_Vundo_390
{
strings:
	$a0 = { eb0d9349feb423d88e44b2922bc3cd60e8020000004f375883c008eb221c2aeb3e20dec4b208a6ecba70ee944258b6bc4ac0fe64d2a8c68cda100e3462f8d6ebde5c6a601e04f248e62cfab02ed48298f6fc8a003ea412e806cc1a504e74a261eb38aaa0 }

condition:
	$a0
}

        
