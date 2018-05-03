rule Win_Worm_Drefir_19
{
strings:
	$a0 = { 837dfc147d248b55fc8b049510204000508b4d0851e8665c000083c40885c07407b801000000eb04 }

condition:
	$a0
}

        
