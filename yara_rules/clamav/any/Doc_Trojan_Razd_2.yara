rule Doc_Trojan_Razd_2
{
strings:
	$a0 = { 20202020202020204966202e4c696e657328??????????2c203129203c3e2022275049524f4e22205468656e }

condition:
	$a0
}

        
