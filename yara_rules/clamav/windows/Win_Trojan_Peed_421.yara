rule Win_Trojan_Peed_421
{
strings:
	$a0 = { 558bec81ec640200006a006a006a006a006a006a003eff15d02040003d570007807402ff1089ada4fdffff8385a4fdffff04c685d0fdffffb7c685d1fdfffffac685d2fdffff7ac685d3fdffff56c685d4fdffffdac785c4fdffff542240008b }

condition:
	$a0
}

        
