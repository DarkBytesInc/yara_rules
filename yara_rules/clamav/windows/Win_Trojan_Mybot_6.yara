rule Win_Trojan_Mybot_6
{
strings:
	$a0 = { 2a02bba6e4c816dee9e87d88451a661d03ac06a9581c5c064e910ef01e3afd19e74ff321ac24292e33383d42474c51565b60656a6f74797e83888d92979ca1a6abb0b5babfc4c9ced3d8dde2e7ecf1f6fb00050a0f14191e23 }

condition:
	$a0
}

        
