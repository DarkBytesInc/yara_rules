rule Win_Trojan_Small_3238
{
strings:
	$a0 = { 2b812ab1d6d84eedffe077f15f1526953f142e95372557b15f9c5971d2e04ed8d6c84ed5ac37e7fd7b98e7e57b843be3393700b1359c00f5359cc0db5f112e9527f66ae1359c95a4bb8c2ab1da5c6535c39d }

condition:
	$a0
}

        
