rule Win_Trojan_Hupigon_485
{
strings:
	$a0 = { 561dbf7a98a59a1fe63abb9ee0d442b9f3f3a07f56c9da3eb361338e124b6471a1d943c6a188712d3175c690e461fe5c8f520734a254757c2402e3dc8d6db6b4ced96547f64a3e497567db052a2f }

condition:
	$a0
}

        
