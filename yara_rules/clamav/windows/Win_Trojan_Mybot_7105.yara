rule Win_Trojan_Mybot_7105
{
strings:
	$a0 = { 3be8aaf60a9da614297ccbd75c866bc070850ed5647f6a4e48d5c13baca996b62d8e6e8c3c21a63ea5a6a2b5674b225b6851c1fae1ef0893260367c4cfdbcca6f3696fb190a68b5943375f1658bed429109048f324c52fe86eed8d8a0033e66a4fa7c367e2b67b7521f68ff59b4d95585f95a282d686758ae148218030563a531da35f2f415efed11ad3cdb3 }

condition:
	$a0
}

        