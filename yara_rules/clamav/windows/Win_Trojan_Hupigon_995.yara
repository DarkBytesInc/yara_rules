rule Win_Trojan_Hupigon_995
{
strings:
	$a0 = { 74c42d1d9387d5effde97bf1edb3155491f82cf90ef4f8ab888611879104e1e20c49f52bb6776407b3159a56993d14263e54eb3f78beb2efa830dae349f0cbbcb0b9a4f790162dc609c8aa9d11418979dcf9a40c2a70bc66a7dbb4ad }

condition:
	$a0
}

        
