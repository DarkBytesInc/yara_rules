rule Win_Downloader_Banload_1551
{
strings:
	$a0 = { c0da126e18c705d25559c234da5b944475b3391ba05c87fe9eab18e3fd88eb131ec3550b7c5d806dc66df1050d6cd33a157c4b1f3c05e1d06f0218a4f75d8f32ae9176a65e155ada8754809646a46c94af26bdc7d632a7a0ab0c }

condition:
	$a0
}

        
