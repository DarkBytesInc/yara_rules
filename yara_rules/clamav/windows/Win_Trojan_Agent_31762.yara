rule Win_Trojan_Agent_31762
{
strings:
	$a0 = { ad773dbae419adc6f46998abc519be31d70d31ab8826b8a1a712bfbca135aba2c456e29cf835e3eee013a653737a7ebe81d9fdb9ee40a9161f17a5efc102b3f18e38999d8169d97855209591f75595a1cf4ddc621d1f45c1ba01 }

condition:
	$a0
}

        
