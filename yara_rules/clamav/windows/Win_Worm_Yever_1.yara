rule Win_Worm_Yever_1
{
strings:
	$a0 = { 6a006871010000686f224000ff353c394000ff15cd294000 }

condition:
	$a0
}

        
