rule Win_Trojan_Mybot_5425
{
strings:
	$a0 = { 8a3988f02e8574f2a83ebdd0dda607ad7d4f32abc699fa9ff1df02e872126df5af4fd24749564d41af58ce77202ddb46157c259bc1eddb1b321f4ef1fc521b6ab6486b1e65dc1a03ed0a51d2faa526f9c630e8b4237703e1436ec27570624bf3a393cacebfc1e4ea9f }

condition:
	$a0
}

        
