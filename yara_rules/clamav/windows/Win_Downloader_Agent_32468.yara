rule Win_Downloader_Agent_32468
{
strings:
	$a0 = { 2c35c13053996a20b2b4041fc32e90155bb201a9c72c882c15c5b198078372e94872ced76ee15b763fd60465060d24b844a9000cb66f7b5f18dbab5a11287059b86dff144a04ab6d6c36122c78b72c91edb249160b1c4a0cb167dd04793eb50470b1b70e16db62c1b2c549994e0fef36f516a8846c1382ca2c192d454199ac1aa649b3851ba75a615edfa7824e8162f1aacb303f }

condition:
	$a0
}

        