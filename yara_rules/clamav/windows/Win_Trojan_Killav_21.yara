rule Win_Trojan_Killav_21
{
strings:
	$a0 = { 56392020060861766b706f702020060c61766b736572766963652020060a61766b7763746c39202006086673617633322020060966616d6568333220200607666368333220200607666968333220200607666e7262333220060666736161202006086673676b33322020060766736d33322020060866736d6133322020060866736d623332202006087362736572762020060a617076 }

condition:
	$a0
}

        