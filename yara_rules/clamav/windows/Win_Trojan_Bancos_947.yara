rule Win_Trojan_Bancos_947
{
strings:
	$a0 = { d9c93082f6ddc1de62d6fb94d625906b02c5fdaf978dc0892b08d94f15d50e6af9caada001fe40bc83810d3cc4178d73b37ca4e0916813f20b51059677344fc36c79d9023aaea6a617fa38e00a92077f5dff781f55 }

condition:
	$a0
}

        
