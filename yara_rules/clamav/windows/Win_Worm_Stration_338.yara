rule Win_Worm_Stration_338
{
strings:
	$a0 = { 115105f4cc2f470d1551540d0b169ecb6c025d55cf69d40ecfd43e178f74c1df1ff3fc8b9c0c238f1c0bb03fa75bec492f600b3f18042143377af17a4100652ef191b2da3f68ce86efe7c4c994e9b799 }

condition:
	$a0
}

        
