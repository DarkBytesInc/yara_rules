rule Win_Trojan_Hupigon_751
{
strings:
	$a0 = { 3dc53ab6100d8af960dc6da47aeb411b0a4f47c727d492f8466964a9d7bb6d15595da224ae985cfbd9ea7e59b2307bb680b922d327fa39745927250095da46a77042a9b81b690ca497be4fd0595f }

condition:
	$a0
}

        
