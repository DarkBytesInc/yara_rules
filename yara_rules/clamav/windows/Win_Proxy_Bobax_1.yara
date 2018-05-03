rule Win_Proxy_Bobax_1
{
strings:
	$a0 = { 10d5f992becf9256bff63ee49a1d69e8080d3cb8b9042c086d526c868ffe2f11539c1dabb5889f12f9fd385e31fd3474d8a3db697dc7f57bbd5d2ea57b1c331274b2ae4dbb12097bffe574a8bde47bb1 }

condition:
	$a0
}

        
