rule Win_Trojan_SdBot_4509
{
strings:
	$a0 = { 67f6f9fefeb55bbb6ff7e5d6e6d63d9d7427399fcee9aa736fd2e94000fc5fe2ea7302f20f54f93fa2c435ee04d8a5cab5f0af10ac76f63ff9a613608f4ee4b2fff556343f00d7d13f492875f2750c3f80ff05cd3fb95f37452c3f008013466430ecbf0c7030fabfeb7fdd74803e82 }

condition:
	$a0
}

        
