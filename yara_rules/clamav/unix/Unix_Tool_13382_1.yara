rule Unix_Tool_13382_1
{
strings:
	$a0 = { cd8099525852bfb797393401ff57bf9717b13401ff475789e3525389e1b0632c5881ef62ae616957ffd4 }

condition:
	$a0
}

        
