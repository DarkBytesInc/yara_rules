rule Win_Worm_Poopoo_1
{
strings:
	$a0 = { 641495ad32f76f6c644abe441b64ab6cc03cc205c87e226b617a6161b542d92a9b37a82f466481105ea95b81b0ca4560c500f68600206dca2c51365b4acf42abb045d8d4 }

condition:
	$a0
}

        
