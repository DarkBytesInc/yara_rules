rule Win_Dropper_Agent_33255
{
strings:
	$a0 = { d5bbdeb2d673965792f2c3b2676cb6cb596b1279e6f9377ec3d7746bca9ce77f8772ff47bdccee601cedcc16f6f3b00ea84144901ac900524804f4042760293222a640abb82559805acc05acc01530150c80acc07d0c12a98d1598a3e98d6bc31179c31f4b4ccee5ffffff1bbf7e7df6f9f7efefdfb7cf27926ecc933e7bfc7c23b5fb2d6f61f55ea96b63d8 }

condition:
	$a0
}

        