rule Win_Downloader_Small_3820
{
strings:
	$a0 = { 00005356be10080000565633db538d44243850ff159020001085c00f849402000055578b3d4c200010397424380f856a0200008b6c243c6a088bf583c5046834210010ff7500896c242ce8fb06000083c40c85c00f8510020000391e75466830210010ff7500e8a90600008bd885db59590f84f301000043 }

condition:
	$a0
}

        