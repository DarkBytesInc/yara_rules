rule Win_Spyware_Banker_2795
{
strings:
	$a0 = { 53f81246b465da6314a9226e826c4aefd421e50e214811849e22ae641096745d3f945c7cce1aaa42e048b8c0f4ec73b7891d49503b2a249354f7843b4e58896098bf6fba4e23ceb8291a2698b355947c3c683f334d5139bd7a4073ac112c83d83777aa4b }

condition:
	$a0
}

        