rule Win_Worm_RPCSDBot_1
{
strings:
	$a0 = { 74055669727475616c410affee877d6f6345780e467265650d4e744f70656e54685d7d012e61648278ff157c012bb79760f3c0c3e805b001b4b84d201180385dfd7ff7000f85e112f0fe0057538cd8a804756aa1788c8bb3b9779f3dbb002389036810064234f7dd7f775068230b50ffd785c0590f84a539894304683213c91e }

condition:
	$a0
}

        