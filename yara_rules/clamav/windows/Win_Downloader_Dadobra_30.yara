rule Win_Downloader_Dadobra_30
{
strings:
	$a0 = { 32ff80eae1f6d22e9a058bba47bd377bdce2464b75c360a9ae134ce2495f2993d15430357cc3ce83ddede8b80c46088b2879b0774383b92c803b12286c8b92add9546144241b1ee08ee4edb9e03439dcb940dcc4ae6c40d81ed8392aae643b2458d4d41c61f6462aa1cc0a443684c595350152d02fd0e76431495a9c66c57f0a4a8de4d0ba08605f7c893f25636d72ce2e6578654f73 }

condition:
	$a0
}

        