rule Swf_Packer_Angle_1
{
strings:
	$a0 = { 0e49496c6c314949493131314931310e496c6c6c31494949313131493131 }

condition:
	$a0
}

        
