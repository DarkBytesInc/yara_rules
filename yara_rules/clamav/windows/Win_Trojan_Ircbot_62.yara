rule Win_Trojan_Ircbot_62
{
strings:
	$a0 = { 073664c305d38d17d4472c93f6f19c5682040ccbd3eae5d851f8bea196cd61b0db9d37049e21e9364c43d75be9d97d1bc039b73b6ffd4fa37f5458fcd0ff0f44d7180a750b701544fdeb39a24bf37f5762fbe17889b07c1ee4a695e0ac78e1000b3c4335d0bb34d6c5a36dce9b922d0e0832cff5142b60ea4a65109c107e08e4db1d848651938d82901f0afe138571ee6f2e97504ea1 }

condition:
	$a0
}

        