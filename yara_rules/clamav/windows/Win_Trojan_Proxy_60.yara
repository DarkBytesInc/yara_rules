rule Win_Trojan_Proxy_60
{
strings:
	$a0 = { 2d83d1de1efea1ed8421f1606989bf4887e450c26ff2a7b83187da358b52ece4a71acb4cc8f98e6265f9851d7a934a3bfc9ab535c777b0d9c8cb577e3cf497103938fd030e37291bb236c1bc656fb133f4d3b0cb73e959b4a0f38b6e }

condition:
	$a0
}

        
