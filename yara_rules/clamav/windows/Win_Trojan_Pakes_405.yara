rule Win_Trojan_Pakes_405
{
strings:
	$a0 = { 14d0993b9826548f5b563f5b91ba6fd294737fccb0e7c32294db8353f7dd399d7d8c795e3dbc31f0a1e6385811e69165881b4478de323b628128a85962813cb875e07c7e91db2cd3c0e06b2422124b75bb2b38e48771446ad43b7906adbcbf2b0ce1244c2236fb2681884f4dae4f9dca1419a0abea6492fe3d583193a0de3080f240a4c1e3da8458da5fc85b }

condition:
	$a0
}

        