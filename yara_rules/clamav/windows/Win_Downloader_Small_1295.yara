rule Win_Downloader_Small_1295
{
strings:
	$a0 = { 79ffffff6a0068c4114000e85dffffff6a00e85effffffe8d1feffff00a3c45fa3cb5fa3c95fa3ce5fa3c75fcad25fc3d45fc4e35fb0b55fc9b15fd5df00000000433a5c43304d4d414e442e4558450000cdf8d6b7bcd3cec4bcfec3fb2cc0fdc8e7a1b0687474703a2f2f }

condition:
	$a0
}

        
