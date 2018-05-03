rule Unix_Tool_13383_2
{
strings:
	$a0 = { 31c00fa25168e795a8ec68de7f373f68071aec8f686e1c4a0e68065b1604310c245a75fa83ec1854c3 }

condition:
	$a0
}

        
