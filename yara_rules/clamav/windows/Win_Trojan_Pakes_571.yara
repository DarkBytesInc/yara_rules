rule Win_Trojan_Pakes_571
{
strings:
	$a0 = { b575be2f59ccfbe39a7b24903060f4163599e41c510d8c473501cc97160322ce3cb2de927c611601600c1f99b00bba8529c10b791fd8208740ceaf99a3a623b99405e372300133170106f444e3371176fad01f0546970b7ff5e0deea4c62a440ad062ba0e3db604b40ae149e4ff5c21eb5bea7bf0b8ab9f27c7d16d86104177113e6abb12200cb981b858f90 }

condition:
	$a0
}

        