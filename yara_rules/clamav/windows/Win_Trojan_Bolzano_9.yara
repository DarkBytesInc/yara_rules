rule Win_Trojan_Bolzano_9
{
strings:
	$a0 = { 576a222bd2c20400558b4c240cd9ffff07fbffffff[0-2]5c4e544c445200[0-2]5c57494e4e545c73797374656d33325c6e746f736b726e6c2e65786500[0-29]3b4658 }

condition:
	$a0
}

        
