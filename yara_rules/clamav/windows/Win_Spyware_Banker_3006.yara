rule Win_Spyware_Banker_3006
{
strings:
	$a0 = { 8e0c7e41f93a7ecae902d578ff4008e9b76dd5fd19d8d1aa0500eec4e86728c40c46483d6b9b1c7244c8d2670a0a12a9ab2903e16f198ae470c4fa4ebde5d612dd5769ca54e6b98e9bbd09da3cc375e4de1874dc38657ac9ca40ee1f15479f366a706e49 }

condition:
	$a0
}

        
