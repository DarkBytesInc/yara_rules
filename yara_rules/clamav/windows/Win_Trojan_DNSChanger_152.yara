rule Win_Trojan_DNSChanger_152
{
strings:
	$a0 = { e4fe01f9930ae6f6e793739f7c151da39417c2bf1ddaf1dcf190c5e88c9bfda294a381269494fd2d1189399e0811e6f99b94fd265409390d962184e39994fdf5e7e486bb930afaa20981fdb8cca53da3e493135ba4d4fd5bbede3da34c1945e394bfc5f4 }

condition:
	$a0
}

        
