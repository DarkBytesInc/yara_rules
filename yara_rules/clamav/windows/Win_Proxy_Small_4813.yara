rule Win_Proxy_Small_4813
{
strings:
	$a0 = { 68060002006a0068681140006802000080ff1504104000 }

condition:
	$a0
}

        
