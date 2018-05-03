rule Html_Trojan_Ascii198_211_4_228_1
{
strings:
	$a0 = { 3139382e3231312e342e323238 }

condition:
	$a0
}

        
