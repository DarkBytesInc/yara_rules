rule Win_Trojan_Vundo_121
{
strings:
	$a0 = { 81ea23863ea183ec04870c24b900000000030c2483c40483ec04b923863ea103d1899c24b1ffffff870c24898ca40000000081c4040000000f1e9e7aca4647d24424f4d38c24a6ffffffe80000000068ffffffff8f042421142468957999f6c14424e3aa311424c14424e09bd24c24a0d34424b1331424c14424c138c14424f111c14c24b0763114248994a4 }

condition:
	$a0
}

        