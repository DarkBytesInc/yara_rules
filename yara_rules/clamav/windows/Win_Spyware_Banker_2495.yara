rule Win_Spyware_Banker_2495
{
strings:
	$a0 = { ac1f2cc40c4db82cbaa2151300c793b0f849d308ac1cafe18c9911fc654d1609baaf580ab1e875a2d45f12675dab5b923eda508146c572f653163199d96acccbfa94b45723ae8b636c5f51931a1bae5f03f3d42e3ece775186b863ab8a6918849d3d04f567cef23e6beaf604310d7984dda94fbcba66241af9447959b5b64a46a151a325530bad4d355e4f93ac5b9a34ea144948b3d8 }

condition:
	$a0
}

        