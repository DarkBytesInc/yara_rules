rule Win_Trojan_Small_3620
{
strings:
	$a0 = { e5d761bf34260beea656b8009b74fb2d8ee77c54d1cea50e92a00a46e94e4809f9d85fbe556cd1fc8d13b213d37d8626b34bfe17cb10a0e17763ee0881b9cff2f004f4791bdedfe7cf665d70d75eabec90ab65a6af2bd0ba7202 }

condition:
	$a0
}

        
