rule Win_Spyware_Banker_2445
{
strings:
	$a0 = { 70501e50a2a86b46babf1f9cb4e2e974766d75915eef5b060fbd910aa844268548b4d236433900b30aeed4e951bc9d2d47e054ec9edf9fbe42596087c91548077f02158a99775d8d4e1a }

condition:
	$a0
}

        
