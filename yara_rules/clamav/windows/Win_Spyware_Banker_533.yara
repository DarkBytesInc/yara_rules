rule Win_Spyware_Banker_533
{
strings:
	$a0 = { 8d85bc7fffff8b551ce81601141c8b95bc7fffffb8385b4600e81600382885c0741e8b45fc8b80fc0200008b8020020000ba4c5b46008b08ff5138e91606462c }

condition:
	$a0
}

        
