rule Win_Trojan_Delf_1589
{
strings:
	$a0 = { 8b55f88b45f08b08ff51746a00e8cc7cfbff6a0068b8e64400ff75f868d4e644008d45ccba03000000e8005efbff8b45cce8385ffbff50e8ca7cfbff83f8200f9345ff6a00e8947cfbff8b45f8e8449efbff33c05a5959648910 }

condition:
	$a0
}

        
