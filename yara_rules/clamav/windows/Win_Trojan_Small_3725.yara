rule Win_Trojan_Small_3725
{
strings:
	$a0 = { c75ff79e709e8f364572cfceb14617d25c5e129375b48ea69daee5385eb1f7b6709e8f2345d092ce5ce153e75bd3b3e65b7497de9c5eee2cbab9e891b3b5f7ce6c5e8f38655da4066d9e8f1e5c74cbde9c5e1abfc75ef9f1b2c88fcd72b29f0e5de34f438fe9ccfe6c9e8f245c36148fd183e5 }

condition:
	$a0
}

        
