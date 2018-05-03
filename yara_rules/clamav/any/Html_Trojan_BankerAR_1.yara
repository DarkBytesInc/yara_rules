rule Html_Trojan_BankerAR_1
{
strings:
	$a0 = { 24d35a898e8b3bae33fcdb8b439ed003530c3b16751424dbe4247bdbbe092a080c014604eb4e16034c3bc2750d39d9e0ff6c2f8bdf3beb75c28bd68bc53fb4847b0d6ea604685a5d5f10bee7ff7b4183bcf87c8bfb8b329e3bf0726c8bce0315 }

condition:
	$a0
}

        
