rule Win_Trojan_W_341
{
strings:
	$a0 = { 2a2e455845002e434f4d002000537061776e3935004569746865722034206f72 }

condition:
	$a0
}

        
