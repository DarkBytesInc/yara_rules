rule Win_Trojan_W_355
{
strings:
	$a0 = { 6467ff360000646789260000e8000000005d81ed21104000520f014c24fe5a83c22c8b1a }

condition:
	$a0
}

        
