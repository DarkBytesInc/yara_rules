rule Win_Proxy_Lager_72
{
strings:
	$a0 = { b489504c8402a22d41c0867cccc4807542801e9931e61bab1acf4f53f4ff8a6086b47e091122febb84885b432dccec7af8329f6d14871fb4c05f64c3ef30c474607947ea6c70 }

condition:
	$a0
}

        
