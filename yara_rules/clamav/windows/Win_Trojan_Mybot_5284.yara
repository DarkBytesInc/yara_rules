rule Win_Trojan_Mybot_5284
{
strings:
	$a0 = { a4db5061f357beffb577d2ea9f45086b447e90c3c07909f0e08648692d0252d81019f97126015fd4d22d3d32011c368ccc0ef690ebc7832da4b34638ab5d9d990b59f71fc2f5fbf710634daa36b2261c1ff4196fed5d16c93f07842929f9997823d7d2d1b4a50bdedc54b78d39f0e282c152841813c9f7074d6b3d6de8383357bd8fb6b33a5fbdd939da }

condition:
	$a0
}

        