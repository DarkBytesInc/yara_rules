rule Win_Trojan_Perflog_37
{
strings:
	$a0 = { eb597d6c14e7999f5d0f6148c7f142d68da32c642143430bc9f9bc7081ac69d7c5bb90c37677d7f62e1cfe80d4ce0d8bc1963d03d1d501dcf1228f5f96b3746ed4ea900e4422b54a7af21f4805353dadb18b6d05252624e05eb81ed1f187094eeb86148c8e64eef7bcb36b2f90937af7b7c77a76de8fe77dbe9fe77ddff1a262 }

condition:
	$a0
}

        