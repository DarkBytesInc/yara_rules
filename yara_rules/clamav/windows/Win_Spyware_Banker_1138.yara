rule Win_Spyware_Banker_1138
{
strings:
	$a0 = { 68849ab87206ef5d37ddba39cfe82cb4ae7a8e47e65e6e690692be1304275576686dd075eec15d4e11cec81e8a51c3f4f05e97e5b7b0a7dfcbd398175ffbfc06afc436663fe198f35725e8aa672e7b2cc1898e8c259e09fe50de }

condition:
	$a0
}

        
