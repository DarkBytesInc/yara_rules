rule Win_Spyware_Banker_1041
{
strings:
	$a0 = { 5ce4540fee3983a7c9350fe78c29247279f7eff25ebd836e49574fb1ba6bfc6782ce95edd34407bc66e606468c67a5c0a2e8632bdb5b684e7311ab16dd01bbc730c6cfadf6910668646a087f782d }

condition:
	$a0
}

        
