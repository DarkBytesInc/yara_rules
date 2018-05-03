rule Win_Worm_Koobface_24
{
strings:
	$a0 = { 633a5c646664676466662e746864 }
	$a1 = { 633a5c3335333435343534332e626174 }
	$a2 = { 25735c796f6f5f25642e657865 }

condition:
	$a0 and $a1 and $a2
}

        
