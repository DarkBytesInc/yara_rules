rule Win_Worm_Stration_650
{
strings:
	$a0 = { f3e6ecbfd2c3c68cc7dac7a2f6202e657865ff7ffecd5cc5d59a9d86d5c5e8eacfdbdecbda9fcccadcdcdaffffffffccccd9cad3d3c69fd6d1cccbded3d3dadb91bf0023040c0518070b1e0305046affc8833c2f3d001dfcfaecfbbabba77ff9dffcede5e5890023414546445f5842507736 }

condition:
	$a0
}

        
