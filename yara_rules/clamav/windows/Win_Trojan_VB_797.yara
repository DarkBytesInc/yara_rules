rule Win_Trojan_VB_797
{
strings:
	$a0 = { ea7d0d9cd4d3feffd98748255b922ec922494fda6dabedd13c6cdb6e6dedb6bb3d6953b33bb3edb4b333d3cc6c6d8495d0258424841042289224ca154225c4ed520a51d1ed86b821fabfcfe77cbef33ddf99c9ddeebd7e7effd7ffbff59ef33de7fb399ff3fc399ff3f8dd7661aaf8123804fc0a34eb942ace003a0136 }

condition:
	$a0
}

        
