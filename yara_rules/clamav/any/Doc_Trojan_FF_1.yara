rule Doc_Trojan_FF_1
{
strings:
	$a0 = { 4f70656e2022433a5c46462e7379732220466f72204f75747075742041732023313a205072696e742023312c204d6163726f436f6e7461696e65722e564250726f6a6563742e5642436f6d706f6e656e74732e4974656d283129 }

condition:
	$a0
}

        