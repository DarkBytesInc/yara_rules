rule Win_Spyware_Banker_2262
{
strings:
	$a0 = { 1320a30eb42b501f1d007b9708f2ba1b0e73c9e1300f3a967573b260b7fab6d7da40bb495938436117c358b998f705d205a3fdfe43b6cc1de9f18ee2ea80f90192f43ba2be541aee74ff02eaa274a2955f717ef95ccef62016da735b410fdbd1ef92f10b }

condition:
	$a0
}

        