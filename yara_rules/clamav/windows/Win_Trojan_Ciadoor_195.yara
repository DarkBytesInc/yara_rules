rule Win_Trojan_Ciadoor_195
{
strings:
	$a0 = { 413e3c77bc5b3d6e492e10d6052be858cce308c05befdb72ac0a9ebb47e9eaef9d1ac605972ee985b493f7106d300400c23390aff757fab02d48b4fd9a43093cc0b39463a1da238bbd9b8ac6893a348a4db834b36453fe8741ba1d8be9ea0052364f708718d1606bc53b5178a93a04d04f3cfc90bdf5d58b813fd93e65d0dd907431b17c65d7a79d65e1a7e1 }

condition:
	$a0
}

        