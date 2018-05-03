rule Html_Trojan_ClickerVB_25
{
strings:
	$a0 = { 68a843400068b4424000e84889ffff8bd08d4d98e88089ffff506834404000e83389ffff8bd08d4d94e86b89ffff5068483f4000e81e89ffff8bd08d4d90e85689ffff5068583f4000 }

condition:
	$a0
}

        
