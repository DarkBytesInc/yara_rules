rule Win_Trojan_SdBot_4009
{
strings:
	$a0 = { 1d9c453cbf4859fcde345e4946201e2953edeaedd857ab4126a9ec1fc124f8afa4c8bd1696e16cfdf644bceeb43595c7bd33b2fa59c43e5da17dd99eb1ac2cb834df9a0e09996b30b77e78afe07b9bf30f310d3d055f6091a9f9 }

condition:
	$a0
}

        
