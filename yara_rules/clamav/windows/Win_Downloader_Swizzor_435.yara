rule Win_Downloader_Swizzor_435
{
strings:
	$a0 = { 2e67cd2caf73d560d94b5ad4c26db50bf6df4ebcd97288abbf7f642d86391dbd70b15fea513bd3f85143fea80a2bb933e61e93145508d827422a5062310792560884c56aa85fec0d86ad6140ce860c688af8925eb7ba21233542 }

condition:
	$a0
}

        
