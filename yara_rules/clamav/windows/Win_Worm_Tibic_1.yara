rule Win_Worm_Tibic_1
{
strings:
	$a0 = { 53455235f7dfed08202e013a544942694350325028fbfb1b60bb6b2e6da8705e005c007376636e9e351084586f }

condition:
	$a0
}

        
