rule Js_Trojan_Obfus_179
{
strings:
	$a0 = { 6c656e677468223b6161613d7177655b6528227a7a22295d3b623d22747228692c31292a3130223b62323d22747228692b312c31292a3129223b666f7228693d303b69213d3d6161613b692b3d32297b652822713d7177652e7375222e636f6e63617428226273222c6229293b652822713d712b28717765222e636f6e63617428222e7375222c226273222c623229293b61723d5b352c342c332c325d3b6d3d61725b22736f7274225d28295b305d3b732e70757368287a5b22737562737472225d28712c3129293b7d652865282273 }

condition:
	$a0
}

        