rule Win_Trojan_Bifrose_561
{
strings:
	$a0 = { 107e5e4504ec0c30ac5eef6da032bc96ee997dbc84b0b27426541c578721b836c1f3234dbf9246a25c9cb3d796e09e8f814adff39ad68754320bfd970180ae4fb279324861bc66e25d743983674c4bdb18c4d6ef1b5d1df1a990cd44d3d081684ef2fe0fd860b15bf96ebf0a29401ca6e68739c8eeae4ea550ebfe32778feeb4b325cb346bbcc3447b14c1e40ed4812a31cc9a4343f7 }

condition:
	$a0
}

        