rule Win_Spyware_Banker_2195
{
strings:
	$a0 = { b2da9fbb9cfbeafe036a7ad57afc901c0839b7b6d49e4e9b99ad82a7959a14b0518f06d31e526f304ec7fbdaff4daef43e1d250fe70352f0796005607fdf290bb5cc2cd085bceb619caa9aad0caaef098eb65255c36ba9672a905c8c1179c95092a10a70 }

condition:
	$a0
}

        
