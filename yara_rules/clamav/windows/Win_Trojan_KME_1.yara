rule Win_Trojan_KME_1
{
strings:
	$a0 = { feffffe932ffffff8b75088b7d348b45408b8dc4feffff8908f3a48b4d44e3088b85c8feffff8901e979eaffff83bdccfeffff000f8597eaffffff85ccfeffff8d5affe9cefeffff244b4d455f454e44242d2d2d204b4d4520656e67696e6520757365642036303131206279746573202d2d2d0d0a00ff2560 }

condition:
	$a0
}

        
