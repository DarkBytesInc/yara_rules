rule Win_Trojan_Lineage_133
{
strings:
	$a0 = { 202020202020202020202020202020202020202020202020202020202020200063760000558bec51b9490000006a006a004975f9874dfc535657894df48955f88945fc8b45fce80000241c8b45f8e80000241c8b45f4e80000241c33c05568d75f600064ff30648920b3018d45e48b4df48b55f8e8000022788d45e08b4df48b55fce8000022788b45e0e800002d30 }

condition:
	$a0
}

        