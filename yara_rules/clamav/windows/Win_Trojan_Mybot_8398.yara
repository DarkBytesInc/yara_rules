rule Win_Trojan_Mybot_8398
{
strings:
	$a0 = { d4479d77fed4d4d40e1dddf9d4d4aac9a3ce3bbfd4d4d4c777e8b8d4ab17ccd4d95167cccccc98597d45cc431abf64e5b18d305510d728b275d8f2442d8a14c1276ca94ce08955302f9133d17589e468b65c6d088a }

condition:
	$a0
}

        
