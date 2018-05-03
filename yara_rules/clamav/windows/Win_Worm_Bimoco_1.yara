rule Win_Worm_Bimoco_1
{
strings:
	$a0 = { 50688079400068a07940008d855cffffff8b0ddc804000bab0794000e8c0c3ffff8b8d5cffffffbae0794000a1e4804000e81be3ffff68786e40006a016a006a00e85fceffff68846e40006860ea00006a006a00e84cceffff8bc3e82dcfffff }

condition:
	$a0
}

        
