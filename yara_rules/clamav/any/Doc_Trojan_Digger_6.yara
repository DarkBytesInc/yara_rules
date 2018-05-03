rule Doc_Trojan_Digger_6
{
strings:
	$a0 = { 732872292e4e616d65203d2022576f726444696767657222 }
	$a1 = { 6243724c66202b2022c2e8f0f3f1eeec2deef5eef2ede8eaeeec20536b79536f6c646965722e20c2e0eaf6e8ede0f6e8ff }

condition:
	$a0 and $a1
}

        
