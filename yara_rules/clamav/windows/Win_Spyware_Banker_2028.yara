rule Win_Spyware_Banker_2028
{
strings:
	$a0 = { f4dca22d9a9a31c7c2921699cb963e0434f000a3e2e10edb0e5d8bba735d38830ec4481cc5eee80c6ad6c7c03da54f174925109d23fffc0f6d04bd6ca757cd60ed6fe39d1248b8d4fde173b8a10f2ac073ac29c066c64704b2f8f62f4ba08c682d9478f87489bb4d1242c72ba3a54d273a0bca5cc47f2c88bd8613298e492c01 }

condition:
	$a0
}

        