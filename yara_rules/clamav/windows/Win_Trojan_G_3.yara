rule Win_Trojan_G_3
{
strings:
	$a0 = { 01b9ce008137000083c302e2f7e800005d81ed15018db68404b200b447cd21b41a8d965804cd211e06b82135cd21 }

condition:
	$a0
}

        
