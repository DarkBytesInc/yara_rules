rule Win_Trojan_Mybot_7436
{
strings:
	$a0 = { a42d0db1d3c2dee47553fd8df7027c974638d01db4b5496c008a290cd74fe60986e7274156c6f022815cb8d4e9ee19f1b8baafb864a336ef7890125c921f3e510bebb209eee2624103ba1e3bcede7a806f303da637f0d5c2be5cd654e9f119f2aa0ac15ce00b6aa918741cf6e208f66b7cf50b93d490d7b49b5cb7685084efb55a466528f12f1e7bfee5aa61bf58a7830e67274fe6e8 }

condition:
	$a0
}

        