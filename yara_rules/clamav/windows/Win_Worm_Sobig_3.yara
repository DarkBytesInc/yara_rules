rule Win_Worm_Sobig_3
{
strings:
	$a0 = { 3435e952375735778885041da07ff26f1597ce002e0c2a2e2a00783a5cd9903c4b2f46a2a10fe7dfbf0f46726f6d282c0d }

condition:
	$a0
}

        
