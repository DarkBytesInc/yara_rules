rule Win_Worm_Padobot_2
{
strings:
	$a0 = { dfaf460c81938c674340e516b5aa4f7ea86c90457d686868f0de687a6868976868686868686868686868686808d668386859e5d668a897973feba5978378f8f8f8f8f8f8e26e2ee06f2f69b31d6fe376eb869479b31a85d06968686869b31d6fe376eb869479b379a869 }

condition:
	$a0
}

        