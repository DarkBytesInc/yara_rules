rule Win_Spyware_Banker_1167
{
strings:
	$a0 = { 53de6c891bf42cd87fefaa2423bd347c6caac2bc9d0ff2b1293da0a66145ce40c51aba4b28f85f463068058cd5a922905ade4f667ce85716a40c015733eb9634b643b0a1511e7baecb5c7684072637cc7aa5f13fdca6b75ab327 }

condition:
	$a0
}

        
