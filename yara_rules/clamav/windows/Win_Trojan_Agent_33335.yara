rule Win_Trojan_Agent_33335
{
strings:
	$a0 = { 847e2dea062c19acb818299ad1206ed4738d7217ba5d81d7c20a4ca1fd281f91b9a3717ba93f18e2bb185a305f15079f74cd435a6d2bf9e817f2d61316da38fd8d8e4fdcc0e19dafb5d38e1eacce5e87fce2a6f1a871130618ddf9b883ca }

condition:
	$a0
}

        
