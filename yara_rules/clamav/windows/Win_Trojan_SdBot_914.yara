rule Win_Trojan_SdBot_914
{
strings:
	$a0 = { e97353581d4fb9a58d941019f607685b0eace506fc03f31e9a9e011d557416d39516b9bdbce123d2d8a7536b7870fb6bc10f1770687a97c062c1314964ab4660ee33a07a9cd7affc2ede58fec2d1245e2a3dbed6797f179e3c066acd89e45ca70f88507296953cc014840ee5ee685be6bf6099129a013a7096734fa229ce080e198ed4966f5594500e39d884f3fbd05f5142fb2bc493 }

condition:
	$a0
}

        