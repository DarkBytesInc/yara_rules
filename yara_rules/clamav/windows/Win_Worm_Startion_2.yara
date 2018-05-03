rule Win_Worm_Startion_2
{
strings:
	$a0 = { 8b44240883e8007425487537ff742404ff1524100010660fb6050222001083c03d66a300220010e88ffeffffeb15 }

condition:
	$a0
}

        
