rule Win_Trojan_Agent_32986
{
strings:
	$a0 = { 4f7f3d262def8bb05ab3eb8fed40d1401ffd2915ce1b2ff9da12997b6d0c17c13b457925f299e62b6674b02d1d82f475d922b6efd35a61d0a0686c5e8120bcf87485cd83a3d86880421fa6eb8c769043ee72ab1b2f1f502a4d61d14d7a0b5550c81aae71d6844d928bab9cbe08d6b2d5 }

condition:
	$a0
}

        