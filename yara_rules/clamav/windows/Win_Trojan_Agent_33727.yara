rule Win_Trojan_Agent_33727
{
strings:
	$a0 = { c15defded36ac42e8cbc1ba02910238dcdc38ab62e75bc8a5c9b7a8da68164644a5307ea31a2c60ac4ccdb9504a634f9c073faeb110fc261f4d28f0562e4373280ded797cf1902f22b47e6ff7bf8da086ab6c3c8889eb9c531c01a8107410d }

condition:
	$a0
}

        
