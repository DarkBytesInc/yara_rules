rule Win_Trojan_LdPinch_128
{
strings:
	$a0 = { 444a25ad9ad3a23f0d32963fb64ca0624397a35b48fcffbf2aac00a2185d95ee28b5094653be8040e51fb8d409ffffff8bca627594c51212ec8fcc2a30339455fca41405c2457ba03633af59ffffffff9893eee3080c8a1a2968354bdcea639dcc7a4fbca24f3229c97f37aa17f15bfdf1bfe0ffd8344c6adcefaf81cdb5a7b4 }

condition:
	$a0
}

        
