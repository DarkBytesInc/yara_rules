rule Win_Spyware_Banker_3274
{
strings:
	$a0 = { 6927f5650f5114ada8d990c1ea1abbe09238825d42fc24a0b69784e6d4a745e8ef94a078d06085e890c85d16e9dab0d03695b27f5045e417b563799f464a9be56ee513da3536328f15e30a5535456f9146a0d0c03d188c5dd46636c4d2b1a698f7f5398de57a6ec21e020084b6291a3112bd1dc83f9042ee235a6788e389f93d0623ad1f0a2000ebf956ede6 }

condition:
	$a0
}

        