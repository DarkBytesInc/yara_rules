rule Win_Trojan_Bifrose_467
{
strings:
	$a0 = { 0e40ec4cb6dd3cc8a7f7bfa58b1906fc3ba633822c51373c88aa535ee1c383d8d88b98f18fd2ce932e34b2d2c77dae5fdcb4b0461c88df0c8b385af7eb2ee7cdd4d4e6cf045f02266b740854016c0832c2479cf7976d1d1e00a55ab949be77ba81a74fadfd9f7748852083cd20b7ac8cd53cefa973fc90ece9c67ef6dc5c702f6204bf30dc2ca9700245ec82 }

condition:
	$a0
}

        