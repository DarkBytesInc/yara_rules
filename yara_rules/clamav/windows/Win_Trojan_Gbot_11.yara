rule Win_Trojan_Gbot_11
{
strings:
	$a0 = { 55fc8bec81c4a0fbffff6a006a0468003000006aff6a006affe84400000083e80303d10fafc2678d16060025ff000000663ddc007475b8570000006a006a }

condition:
	$a0
}

        
