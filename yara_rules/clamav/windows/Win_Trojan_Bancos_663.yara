rule Win_Trojan_Bancos_663
{
strings:
	$a0 = { ebe5175e369ae97862bd5ff1999e22f02d601eebe3108b890e1ace699976f9ff4592fc38b33e65c1809415200107d0933b9b2b8140f0b53c54162c9f0a29b21cedfb3a46 }

condition:
	$a0
}

        
