rule Win_Trojan_Hupigon_1701
{
strings:
	$a0 = { 3aa6864bd88b914cc722e366b7c5f7a888df0dfe83f80dfb14aefcb985be14cba1ae090ba20f43e01ae8538e9837f64d7046e37fecbc7f6b9ce5d3903aca23f75fd1fa45c0367fc2027163bb1f403aef6ad576bb76a59f8b740a0d5c6f02841ab636a48bbae5dbecc7a6e54bb0c615947255e21eedc31272 }

condition:
	$a0
}

        
