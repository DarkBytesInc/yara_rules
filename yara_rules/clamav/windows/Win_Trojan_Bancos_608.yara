rule Win_Trojan_Bancos_608
{
strings:
	$a0 = { e7a419f2d84c5138ce8f69e7ac72868b2ae93091a921c1e2aab90b4e8c22adb722c9b40cebbc521150785d2ebb4b5566c9ca79c5ca69f07307c2c9a230a8fa22674e0908a96224ae597f364334463347c2eaebf3a10119140974f674c5105604b0f4b24d70c50e66b3a58f3535cb0929a2ec8b2851dd415519a455934f6df1689a6f10a170cfdab75cf2ee96da70b1d9d04ab4a4dc24 }

condition:
	$a0
}

        