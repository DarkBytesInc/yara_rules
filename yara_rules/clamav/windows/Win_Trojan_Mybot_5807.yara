rule Win_Trojan_Mybot_5807
{
strings:
	$a0 = { 8df9d47e28529506a8bf03a611a451897aeb04fab7aeaa7dd0eb6cfdf470503d117f1987645505bf9931747da6be9289e2904022a3daef4e4d18265b8d459c13a2869247a9a837c4eb92757612b10800c4efc8e3d060f8f33031d3b276578f971c76258a3423b61e44ee3fa4bb0a871f06d79bde18677a0e431deffe1f09dd632e70d14b58c06b078028bad2f1123daf9cdf63a556e0 }

condition:
	$a0
}

        