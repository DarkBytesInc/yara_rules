rule Win_Spyware_Banker_2038
{
strings:
	$a0 = { 8d21c2f83ca8832af14ac3792cdae8df1fa6516b8fc1e2a6e9c96c00f863d08ad242947c4e241ca9e1698243524fffcf7758ff8ffc6a40fbeaa3eab1abe52b467e18bde4f218f94284d46c754813a16dfbd88ec72b9424a885ccb7a6e1bceb5640e8d07e2d0fe9a6564d9e3d32269e79ef78a8a6dadbb8d8c2cb4450fe8efa4e }

condition:
	$a0
}

        
