rule Unix_Tool_13732_1
{
strings:
	$a0 = { b024cd8031c0b058bbaddee1feb969191228ba67452301cd8031c0b00131dbcd80 }

condition:
	$a0
}

        
