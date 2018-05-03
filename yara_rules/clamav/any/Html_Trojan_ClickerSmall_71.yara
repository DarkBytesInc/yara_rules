rule Html_Trojan_ClickerSmall_71
{
strings:
	$a0 = { 426973207d7bd7f661742072066b2d537079772665206465b6fffeb61a630264206f6e20792e50432e0a573d64bbedb6b9761c69 }

condition:
	$a0
}

        
