rule Win_Spyware_ot_222
{
strings:
	$a0 = { 738f6b725e481ae73623c1d9ccaa4dc431a58786ca05b8ee52fe06ba50587c1bcf433ea6a9c54b2ed508a8175ef75de6135870d8b3c9f26a5f69eeac911d01c9b0be9ff140969bfa8b233d4d3ee4f8c003ff387d5e49e7936e509fad508c141b21e37d545dfab6da7b54712aa9250003aa686e2bae7ce5861e3527a188f95c40e34e7a37f24418186b639c4131a2c0a8 }

condition:
	$a0
}

        