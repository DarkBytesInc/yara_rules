rule Win_Trojan_Hupigon_299
{
strings:
	$a0 = { e71f7c3ec8b75dc989c58cffc2b28f28304dc8c51db72564d3cd2ab8ebf042f865e83e4121783d7cb161fcf81c059760eb86633664be9ff99dec8d791f124ffbb67ad4f78551010a211ea65ee54d1f57fcf674c15c679c38765b }

condition:
	$a0
}

        
