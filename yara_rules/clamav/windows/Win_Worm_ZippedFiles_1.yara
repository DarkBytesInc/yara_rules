rule Win_Worm_ZippedFiles_1
{
strings:
	$a0 = { 13a1fa397b23464fd60c2c46d9dc13bf7930de3793116fd7c22b381668181702d22ed412c2d5421f7d39a20a42acf9a391e7324b44f72f345f70b9b1167511c525deda3b4286f71e90dd0fd7c73fec55 }

condition:
	$a0
}

        
