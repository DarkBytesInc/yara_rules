rule Win_Spyware_Banker_2738
{
strings:
	$a0 = { 923823f944a059f6c4ebe14885030a583b4a046ef92aec7e52543efe2d27210160e80a960e191ecb7377abf4ab14c8c8295fbd2f39e2e99056e1aade918660ccb9fb00fc8000d4ee8c8a98dc76a7 }

condition:
	$a0
}

        
