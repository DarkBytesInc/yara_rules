rule Win_Trojan_W_259
{
strings:
	$a0 = { 56cd204100400083c410817c06fc2e4558455e0f85c4010000817c06fa4655434b0f85b6010000 }

condition:
	$a0
}

        
