rule Win_Dropper_Small_1606
{
strings:
	$a0 = { 8b45f0508b8d84faffff518d8db8fdffffe8830500008d8db8fdffffe8840500008b958cfbffff89955cfaffff8b855cfaffff50e86605000083c4048b8d84faffff898d58faffff8b9558faffff52e84b05000083c4046a016a006a008d8588faffff5068404040006a00ff15f0304000 }

condition:
	$a0
}

        
