rule Win_Worm_Gaobot_837
{
strings:
	$a0 = { dba69fc852a2800b9427a0b506116cca3c38762529e0d767674839cd2d20443e29bcc837b056af3c865a4214c40f59e40568d23f640b09a6b224e1b491e242a69bc7fdfc699aaf5c984e0cefc8286f28813a79198b0af999586a11f1c4218e8473fde962787a34b05739efc663 }

condition:
	$a0
}

        