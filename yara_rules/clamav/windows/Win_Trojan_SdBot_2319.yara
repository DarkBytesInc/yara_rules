rule Win_Trojan_SdBot_2319
{
strings:
	$a0 = { fc257d67dfb5cb2c77f1ff0eebace24f9eb8a295924891c11be0bf128be0414302574b98ecf91064f25cc47749ffe1ed9e8786e20ea681bb6a0801d8bb5befec96b74a29dc74906420120653b0ee485110083d2430 }

condition:
	$a0
}

        
