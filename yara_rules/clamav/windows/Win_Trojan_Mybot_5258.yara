rule Win_Trojan_Mybot_5258
{
strings:
	$a0 = { 23a15218174539fab2ceb9855775f108034a8753518bd1575fc4bcb5ae1116da14b21c105368ce5b2d712e7ef201cdffc30f6e761a47ee53ab867e8dcad38a97d57098547872446f86856e9323061d3a01630385cfa8f1e3b11e0b3fd1886aae3362fa4afc56ab6a6d34b1d86ac94a9074501399176cf7caecdee2ffcf9f0a0e8a6b70f70efec8d0528551406d8407f4ed5b1d9c2e85 }

condition:
	$a0
}

        