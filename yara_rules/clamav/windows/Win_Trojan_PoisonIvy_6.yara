rule Win_Trojan_PoisonIvy_6
{
strings:
	$a0 = { 5f4576c85ef96e0188f166292de91e083fe11618fb9d0ee8ef9506202b89beb1e385b6109c38aeb01c36a621142e5ed00626561904df4e00cdd5460034cdfe9998c1f6393c7cee703c74e6e0366c9ee83f6096e837188e81221486d923083fc0f20637d1d5bc2f1946b6276090aede202aa4d631485cce494454c608704c7f384844772946fc6fb042f46751eeec1fa864e417e0ae9c }

condition:
	$a0
}

        