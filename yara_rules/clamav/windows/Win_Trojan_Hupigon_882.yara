rule Win_Trojan_Hupigon_882
{
strings:
	$a0 = { 47c76abf347d84e1b55bac1166020fc2afd566f066650329406386ffaefffb1ef9f4f7b463ec740271b943b327d4ff7a682b40c7c8bc98dbb537887ddbcbf9dce4f64c5a94c79687d745c2c87f9e14246a5fd48ceb0cd7c6ca4ff2d7ba9e51 }

condition:
	$a0
}

        
