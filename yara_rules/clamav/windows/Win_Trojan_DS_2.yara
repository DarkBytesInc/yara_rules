rule Win_Trojan_DS_2
{
strings:
	$a0 = { 2e657865207d0e633a5c6d6972635c64732e6578659a000048005589e5b800019acd02480081 }

condition:
	$a0
}

        
