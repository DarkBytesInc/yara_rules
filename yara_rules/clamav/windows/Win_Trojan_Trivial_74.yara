rule Win_Trojan_Trivial_74
{
strings:
	$a0 = { 33c9cd2193c3558becb4408b4e04cd215dc20200b43ecd21c3babf01be9d01e8daffba0001be9d0150558becc74602a1005de8d1ffbe9d01e8d9ffc3b41abaa101cd21c3ba9d01b44eb93500cd21c3baa101b44fcd21c32a2e2a00 }

condition:
	$a0
}

        
