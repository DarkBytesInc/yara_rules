rule Win_Trojan_Hupigon_1551
{
strings:
	$a0 = { 087058865ca033f5ebd5c00e812d0817b4959dff6aa9b0cf625286c44d56cfbb8682e41a3792a806017bb910c42c81a8d4e6daf09e801e3492f98adaa5b59dd197ef9fa9e72befa788bb6d608680 }

condition:
	$a0
}

        
