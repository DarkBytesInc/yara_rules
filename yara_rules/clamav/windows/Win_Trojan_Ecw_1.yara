rule Win_Trojan_Ecw_1
{
strings:
	$a0 = { 5052ba8d01b41acd215a58b800005152ba7701b92000b44ecd215a593d000074153d0200740e5052ba3101b409cd215a58 }

condition:
	$a0
}

        
