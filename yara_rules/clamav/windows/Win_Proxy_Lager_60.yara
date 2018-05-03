rule Win_Proxy_Lager_60
{
strings:
	$a0 = { 72e13c83ec0d4fe5e93f64ccbdc78afc78f4f8b78c9d6f210c2ffa8ba9d753cf1eee86316df96a84ed20be5c9657913336e01e7ab57e127351580086b2fc82b4172269b92e48 }

condition:
	$a0
}

        
