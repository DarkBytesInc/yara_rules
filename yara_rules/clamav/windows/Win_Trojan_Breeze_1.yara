rule Win_Trojan_Breeze_1
{
strings:
	$a0 = { eb02daca9c505351521e06165657a12d02a329028b1e2f02891e2b02b41aba00f0cd21b44eb901008d162302cd217303e9d4002e8b161af081fa4c01722b81fa }

condition:
	$a0
}

        
