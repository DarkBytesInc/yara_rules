rule Win_Spyware_Banker_3330
{
strings:
	$a0 = { 98188f4ca4e028fb37af271d65ddf4133431115ffd0e2eeb9de2c52d8f34bb515f235dfc1da2f1db3ab938a2055091e86d76f55fc965ee9c272faf991ba554e4486f47984e9bbde95198ce9ab7c80495a0a44ea3b0 }

condition:
	$a0
}

        
