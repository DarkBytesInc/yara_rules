rule Win_Trojan_Mybot_8430
{
strings:
	$a0 = { 814a78bba6fc4126df808a9495c2db51a619ec4db0cf55b0c111cc7c435c29c97ea3d7eefc94305718b4ff4ed077a9508caddc9c1377ae38a0b13ace058ca5bb8a66f3b678a9f2e3e515f09ef805b6bfb1b78c0ada }

condition:
	$a0
}

        
