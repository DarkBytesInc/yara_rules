rule Win_Trojan_Mybot_122
{
strings:
	$a0 = { c40adde66ae1886e2ee0bdb4597c7f6985c5ccc8a38cc14d6f5e3ec140bbfcdf04eb0c07af58b25c67106ba52a6b2053e390354ace63c16b532c75f82933460a8f7628816c79ea02bdef50b129da36e3bb65281db80b04d59cde025fad64a979bf881b95b0 }

condition:
	$a0
}

        
