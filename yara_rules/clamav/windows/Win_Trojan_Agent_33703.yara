rule Win_Trojan_Agent_33703
{
strings:
	$a0 = { 6191949ac3f987b92dbefdde1404a1d3d3abef6739b0bc527c4dd4fbd6a159633220882195039aae73a68ed65dbef609af98c39f246058eea9bf9d51f07ec2b6c332ad53a0ebba1e9e739eb99a16a2e607bdd741846362d26ed5a6d623c596 }

condition:
	$a0
}

        
