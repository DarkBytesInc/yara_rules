rule Win_Worm_Colevo_1
{
strings:
	$a0 = { a899a9134aba242ea98b7d4e5d9fbc97c167baf036b78f5ddc23dd16a0d05ba5f6431e7b5d42d7bcdde4506d657a6d42be7f8dcfbc61926e385b6edd72e253f57da1d0247130151ac8f0ddfcd4d05ad3 }

condition:
	$a0
}

        
