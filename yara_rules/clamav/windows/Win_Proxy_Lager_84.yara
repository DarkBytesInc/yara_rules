rule Win_Proxy_Lager_84
{
strings:
	$a0 = { cc1d6a79f53698428875c97056854de4bbf785d491f0e0ef919199e996f55455dab29d79f128d2e1fb1088fc7aebadb0fc1acc849e75ae1b37cf3bb33cd4419e00bb33a2 }

condition:
	$a0
}

        
