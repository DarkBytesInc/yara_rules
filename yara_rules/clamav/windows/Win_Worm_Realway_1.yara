rule Win_Worm_Realway_1
{
strings:
	$a0 = { 6463632073656e6420246e69636b20633a5c[0-14]5c7265616c776179746f6861636b2e657865 }

condition:
	$a0
}

        
