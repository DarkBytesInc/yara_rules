rule Win_Trojan_Bancos_1378
{
strings:
	$a0 = { 5d9a0379f2286adbcd6cd295031ea409ee10c9f1521187fbd80b4c460f52e13fbb56d55549cf65435a222b0269b62cc5126427ec609a0c42fc9ddaf0f3d8e54994ac40673677a5ca01bb9975d66e2d3cab33db2dabbbad09ba73bbddeca117d26fe390c23b02049d }

condition:
	$a0
}

        
