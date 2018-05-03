rule Win_Worm_Koobface_52
{
strings:
	$a0 = { 558beceb028387eb068bd2f7db00008d357cd14200bf19fe450083c14881efbd013f2181cfd1a285b8 }

condition:
	$a0
}

        
