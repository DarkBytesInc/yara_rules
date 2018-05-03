rule Win_Worm_Trafox_1
{
strings:
	$a0 = { 83c404808571234000058d855c23400050c3eb01e88db57923400033dbb9f40200008bfe8a064634 }

condition:
	$a0
}

        
