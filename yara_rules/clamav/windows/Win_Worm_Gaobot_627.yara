rule Win_Worm_Gaobot_627
{
strings:
	$a0 = { f824fe79287516ba5a269b6c49193f57ccec9957e06338295a349e4cdad2533806c616bff65c153d07b4f7b8cc0aa07a197d08cbb67b4c631586661f1613edea54b2e378956e0be4afbe74c0653013e4f3b69760786ba56dfe269f859b8efb6cef9c995cd291ab314ddf501d345c1b88769c4694afd51640a2c52f2fa63bde2cdfdfc7804f1adc465b3951bc708a5311bdde9185c9 }

condition:
	$a0
}

        