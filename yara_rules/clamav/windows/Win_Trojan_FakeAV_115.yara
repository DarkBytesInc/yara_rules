rule Win_Trojan_FakeAV_115
{
strings:
	$a0 = { d229c229c2339564fdffff139568feffff81fab300000072181b9534feffff039534ffffff1985bcfdffffff85b8feffff2195c8fdffff2195acfeffff8b8528ffffff31c8198568feffff298538fdffff3985fcfcffff76198b8d6cffffff098d04feff }

condition:
	$a0
}

        
