rule Win_Spyware_Lineage_431
{
strings:
	$a0 = { 542e4558450bbc510b704d41494c4d4f4e23f301ea4b4156504657e8e30eeff15fb4f868f24e755f5f0ce89d8b4d0889414328145750f87258ed }

condition:
	$a0
}

        
