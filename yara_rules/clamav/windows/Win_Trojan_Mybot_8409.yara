rule Win_Trojan_Mybot_8409
{
strings:
	$a0 = { 0fd14242fb918c3296bc8299f7c8bb20e3ebb767764d1bc9a23ec3ce385c02a63b213b5b8c7f3fbbbc97bb744ff408b37b828f31e01da4e4c12684ee79d3c111fc0a7d27bdb93881c4f4f5a8ba19fb586f7a2af4ff }

condition:
	$a0
}

        
