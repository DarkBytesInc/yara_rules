rule Win_Trojan_Small_3917
{
strings:
	$a0 = { 3de4891f17bb97061786fe52bf99f5fd550ced42406f05fdc9a9f57748df3de9086fb00abfbb02774cbbab55bf99f5fd5564ed424067c87a50acfd8998d722765513880e17bb0277bcbf021740fdbd021365b8fabf }

condition:
	$a0
}

        
