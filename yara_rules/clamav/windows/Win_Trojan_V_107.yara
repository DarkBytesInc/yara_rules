rule Win_Trojan_V_107
{
strings:
	$a0 = { 505351525657061e0e1fe8f00083ee1b8bee45803c017426b9030046bf0001f3a48bddc7070001c747020000c7 }

condition:
	$a0
}

        
