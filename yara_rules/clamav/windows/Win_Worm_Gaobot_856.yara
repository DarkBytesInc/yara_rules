rule Win_Worm_Gaobot_856
{
strings:
	$a0 = { 5c6a20c26ad341605ae5e1c87fc8852dbd572284cd92c1c88f3e689df9ca3f322ca93a5a6ea02ed0cde2870ceb2fbbabc80e65a1f6917f6fb1ee65c417d2edab1e90e2d8e13478cbcbc6537bdaab290566bc59b6f914bb505389c3d33d22b9e5750f4d17a68c9de1b4d9d0793d }

condition:
	$a0
}

        
