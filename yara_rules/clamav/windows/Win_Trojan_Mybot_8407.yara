rule Win_Trojan_Mybot_8407
{
strings:
	$a0 = { 8bb2d129fb26f1ea5dfaf5f7c7b5177a8f90f034da2aafa94531d6b4f9081df2ee6680631f3bf7acf56627b414094c4fcfdf3404e2f6434cbf71957be4d36fe77fd70e4f7f53347e6695b613f41fab8a863f061894 }

condition:
	$a0
}

        
