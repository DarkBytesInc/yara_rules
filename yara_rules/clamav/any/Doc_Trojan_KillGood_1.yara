rule Doc_Trojan_KillGood_1
{
strings:
	$a0 = { 616e7377657224203d20496e707574426f78242822c5fda7daa6d2a6d2a7413a5ca662a5c1b0ea3733a67e32a4eb37a4e9a558a5cdaabaa7daa573a4b0bbf2a657a672a94f3f222c2022a7daaabab2c4a440a6b82229 }

condition:
	$a0
}

        
