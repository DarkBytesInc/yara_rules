rule Win_Trojan_Mybot_7562
{
strings:
	$a0 = { b8f1640c1237c4082311e44957096d420db96daa5db54d18d692c61add24c45fab64b0bc169e6ffc8c29e8a40b7916167cb590d288844a05ff14e28301c672f48a45f2d985410e20846f907a578d55986137b60a06d03bc1771db541b4bc502b41b820d603fa24ce1685fe275d73aa428b8a9bff2c6a75b20b5b6addc687d0ea8e907b92bfcc4756b749998e6a111f2421 }

condition:
	$a0
}

        