rule Win_Trojan_Xuxa_4
{
strings:
	$a0 = { fc368b2d81ed030183c402eb04903030013e81be1201303074298db647018dbe4701b901042e8a9614018a0432c2eb }

condition:
	$a0
}

        
