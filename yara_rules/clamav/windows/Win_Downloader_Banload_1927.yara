rule Win_Downloader_Banload_1927
{
strings:
	$a0 = { 9c885ceaecb8647a09c4d95da63d04834746ba447ee7992449760f4fcf28ad087265701e1018c8377e973078008480f28c47f4f7702fb27d304db007f89b1db45092c79bf7615591e7f640f0c40df6f7f8c0ecacd06a0314115026c54bba1346fc36ce7e32200c21f6e50bf36842264bc2fa0b4d738106277f171c45444365d76c4d5f420f54240334469aa6e99a046c073ca474ecb6 }

condition:
	$a0
}

        