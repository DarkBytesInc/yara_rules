rule Win_Trojan_Note_1
{
strings:
	$a0 = { 70ecfbff8b9558fdffff8b45fc8b08ff5134c645fb4333c055686150440064ff306489208d8554fdffff8a55fbe81eebfbffffb554fdffff68cc5144008d8550fdffffba660000002b1570a84400e8fdeafbffffb550fdffff68d8514400ff3574a8440068e85144008d8558fd }

condition:
	$a0
}

        
