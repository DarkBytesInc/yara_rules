rule Win_Trojan_Gobot_10
{
strings:
	$a0 = { 3237f94d79ff5ffaff446f6f6d207370726561646572076f756e642061207669637469448702de6d3a228b0843bc1f00bad0c7c3b15a }

condition:
	$a0
}

        
