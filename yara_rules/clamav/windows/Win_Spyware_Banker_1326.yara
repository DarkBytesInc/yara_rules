rule Win_Spyware_Banker_1326
{
strings:
	$a0 = { 44fc7f9a70d025ea6b1452ad6aa46fc2ef9abe1d7a84937ecb6e2d1841f7969874dbec678df649c98daa3ffe5877172b3fa8215c28d5532c957c57346c54db33aa10cc621ab5f9088a566039804570874d9cfd2293dca975adde78b4fbc2c4af680cd393bd6219bc02e6d4a6a74e085d53bb3f52274f356e5dc42f5f9b41bc7e57b5b5a0eeb64a80eeda231ab8ef561720c232cd94b9 }

condition:
	$a0
}

        