rule Win_Trojan_SdBot_2131
{
strings:
	$a0 = { 8ebdad347e21c040d0b291453ebb41d33ebeabc66339fdf894c6d72c1cc930462393dbb7f2a80edf7fe4b4c9281c2f397e17fa5482ea5d0efb6fe0499a1305b9b1af8c6025c17b6992532b29ea4cc1ec3ba103e92525e36239c4 }

condition:
	$a0
}

        
