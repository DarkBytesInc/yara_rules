rule Win_Trojan_Mybot_6556
{
strings:
	$a0 = { 20ed45e1be4c5cdb4c5adf31d5b9b3bd817f59103ab8256a499a93f6b73b50ee454c424ddb7a7bad809aa1ddd139d81b0f0d5e8832a2153bcf3ef9407fe41ee30b1527f7ec19a93bcbedfa6dda04a0a6d190c84c36f794d95c0d21c8840ccd813b1bb2ba38c8f13c28b64213e715556bfa5af5d76cf3390ed9bbe879b036ade7f0fcc87e5b37074aa8325efa0ad30c43092bfdeee18c }

condition:
	$a0
}

        