rule Win_Trojan_Amitis_12
{
strings:
	$a0 = { d90c768e10f3900cc423d807724006e4f4103c2bc8e438534f390006c521f38225ff668480df296d6974697320312ec5ffbfd0342ecb506c7567696e204d61646520627920dd6ef110c965df7368237c005b }

condition:
	$a0
}

        