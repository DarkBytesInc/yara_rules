rule Win_Trojan_VB_1647
{
strings:
	$a0 = { 6c6961726c792e686f676e7574002d4c4209004800000093b2000048000000030008000bf2574720 }

condition:
	$a0
}

        