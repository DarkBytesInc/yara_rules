rule Win_Downloader_800_2
{
strings:
	$a0 = { 4d507c082e45d137cd64a9668b0b86d1d1a87d08b1146d9135a57d56da0a05cf7dad362bd96a84134696088bd32d364bb36d3f21eeb1d825aa38318110673bdbb25cc035f537451f453c2433f2f36853d5487365c6e2c29cdd142b1a2a73b5e9bd33e31b889a60c589e8e5524876b2881846a2c5ac8c058d51c0b1fc }

condition:
	$a0
}

        