rule Win_Trojan_LittleBoy_1
{
strings:
	$a0 = { 81ee03018cd80510002e0184c3011e06b8ec62cd213d68537503e98300fa832e0200518cd8488ec026833e03005077 }

condition:
	$a0
}

        
