rule Win_Spyware_ot_31
{
strings:
	$a0 = { 1f2e75731e691f72c4203a29c7f65dde005365617273696e67262066cd93fff1fe4a00d6bae45baa00aefbae07233332371730012573205b }

condition:
	$a0
}

        
