rule Doc_Trojan_Walker_4
{
strings:
	$a0 = { 5772697474656e4279203d20224c6f72645f41727a20205b534f535d207b4623537d223a2056697275734e203d2022565f4d616e223a204578697420537562 }

condition:
	$a0
}

        