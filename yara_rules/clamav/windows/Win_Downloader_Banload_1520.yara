rule Win_Downloader_Banload_1520
{
strings:
	$a0 = { adbcb079bcba58d2809c97a032a11f933b0db2e3562f5289d5cf1d84f3043ab71eeaf0fa15bcfc4d38c1bc26e44cb6c4948ae42affe4fed4238bf379326e704196eabc4611c3084eaab488c750eea2a2abbd8d3abc8d1a0ae65385865a1eda37e755b56a2e6233b088829df9fae3ea630b7b072f0d6c }

condition:
	$a0
}

        
