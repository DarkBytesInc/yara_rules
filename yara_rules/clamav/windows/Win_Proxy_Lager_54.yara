rule Win_Proxy_Lager_54
{
strings:
	$a0 = { 0ef1e6d00a21c66764c50bfb1e8a5adb6a2646dd08293075f02a5a35a2b8d9edef3abed827fae0d50951e6d07738dadf6f4f19024b4462a2b23b01f2ff7e07dd10cd8da49fa1 }

condition:
	$a0
}

        
