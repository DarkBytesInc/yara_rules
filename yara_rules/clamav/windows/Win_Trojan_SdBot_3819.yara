rule Win_Trojan_SdBot_3819
{
strings:
	$a0 = { 65204ba35eaec5de28dc5b5d9ef6e69e50a8e45b26d554d42ba43b01399b51a827cf644b2e904d88935c10c7bfd50a463c3d4db1f8c59b2f39c3b9bf41d715a102c03ef1c6be3dbdcdf65fbb3aba380ec57d97a13a86c27a3c849b07e8b2313374bc }

condition:
	$a0
}

        
