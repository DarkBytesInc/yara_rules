rule Doc_Trojan_Jishe_1
{
strings:
	$a0 = { 4d7367426f782022baafcafd5363616e446f63756d656e74b7b5bbd8b4edcef3b4fac2eba3accfb5cdb3cedeb7a8cab6b1f0a1a3222c2076624f4b4f6e6c792c2022cfb5cdb3b3f6b4ed22 }

condition:
	$a0
}

        
