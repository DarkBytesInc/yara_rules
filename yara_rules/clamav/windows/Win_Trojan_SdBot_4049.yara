rule Win_Trojan_SdBot_4049
{
strings:
	$a0 = { 7ca8011a67c16f756d37fa8a4842d625da00a14675db284f655d804c1cc210a043519fae8647e20cd37ffc518e3da5bd6ea0698c5b761fdbe249dd860bca9cb91dd4ffa504758340be69dc9cbf2442fd0192fe82f3a2 }

condition:
	$a0
}

        
