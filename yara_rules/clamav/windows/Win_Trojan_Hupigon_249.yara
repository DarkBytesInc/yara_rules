rule Win_Trojan_Hupigon_249
{
strings:
	$a0 = { 9f7283cac1c1cfea0747a96020cb7c5084623ec7705020b9ad79a8fc67dcd9424d1b881019f6bbff189c2f8fed1d5e3cd0104396415a7e3cf14497cebfa96dc18b7b104eba2c7ca429abfc9fd74bf0ae83db4d6230a90268ebba6cd2a44e0dabf220229189bf744ac548ac22de62 }

condition:
	$a0
}

        
