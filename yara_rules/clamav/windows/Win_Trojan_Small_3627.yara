rule Win_Trojan_Small_3627
{
strings:
	$a0 = { 554c7f09e4ec3f2255d8984534fcb498fc49fd45ef651b71ddd4030b6878803aa376bec9b251d74686fc1bdf1d813fcbe8d65fb53b00bd8a79810eedb7e02f21c6c5018b43fabf5074a403ff7693fd507536f5623f5b298b22ef }

condition:
	$a0
}

        
