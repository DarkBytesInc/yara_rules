rule Doc_Trojan_NPR_1
{
strings:
	$a0 = { 5469746c65203d2022c4e0ededfbe920efeeebfce7eee2e0f2e5ebfc20ede520f3f1f2e0edeee2e8eb20f4ebe0e6eeea2022202b2043687228333429202b2022c7e0efeeecede8f2fc20efe0f0eeebfc22202b2043687228333429 }

condition:
	$a0
}

        
