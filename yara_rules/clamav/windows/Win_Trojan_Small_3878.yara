rule Win_Trojan_Small_3878
{
strings:
	$a0 = { 687e214000ff35c8bc4400a1d0bc4400ffd06a00ff35f0bc4400ffd083f80074d58bf8688a214000ff35c8bc4400a1d0bc4400ffd06a0068bcbc44005768f0b54400ff35f0bc4400ffd0 }

condition:
	$a0
}

        
