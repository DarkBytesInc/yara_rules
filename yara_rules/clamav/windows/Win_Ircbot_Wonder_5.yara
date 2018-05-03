rule Win_Ircbot_Wonder_5
{
strings:
	$a0 = { 21b43ecd2161c3576f6e6465722056697224537a6c61746b6f20546865204272 }

condition:
	$a0
}

        
