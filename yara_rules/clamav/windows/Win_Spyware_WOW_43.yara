rule Win_Spyware_WOW_43
{
strings:
	$a0 = { 875a7bab7956c0c55221a768aefd158915e1cd95f4e1f4f87189c1d0628aae3cfb94378c390799b9c544c71a5b320f5bbcb19db1ef440c1d87217686f231295006abb5d2fdae37968b07b4ffde37cdcdff9fa03fcd5895b54a8daef49b55fec20c21 }

condition:
	$a0
}

        
