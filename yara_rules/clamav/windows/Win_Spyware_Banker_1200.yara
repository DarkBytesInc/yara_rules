rule Win_Spyware_Banker_1200
{
strings:
	$a0 = { b859cf72c713dc00b3381b7dbdfbeb536377fd84eb6f84a0389764bc579f2f6eb16aa385675aa57c4d3f181f663be1b6280d37a388e980ac3a5041b4af17b747b22f2dc980a2dbcc1482b534f3f169d4c695343e9ce23d109eee }

condition:
	$a0
}

        
