rule Win_Trojan_Dialer_643
{
strings:
	$a0 = { 558bec518065fc00565733c08d7dfd6a0466abaa8d45fc8bf15068406b4000682c6b40006802000080e882f1ffff83c41485c07411 }

condition:
	$a0
}

        
