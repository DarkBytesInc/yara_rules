rule Win_Spyware_WOW_41
{
strings:
	$a0 = { b18dc2aa68e06de025910eaf4163047196dcaffc14df11237a4ddf22a46c89f56686c82850fe9d6186e943f9f6f95edaae9559cabde3a765c7a6ceaf809b8569b46737f6fe9fdfcc753f1175cbf7523e72415fb06ca1ffb0acbc }

condition:
	$a0
}

        
