rule Win_Trojan_Spambot_83
{
strings:
	$a0 = { 4e124a31bcdf5313d0b92ca62d2b15e922d288ffffffffab5fc8ca544290a6781e9fc7acec909f56cf63d6efe3c73e5b40c16424a6743eff1ffef715a31b8c0f455b95868ff85f8df5234e94ce0ab01f9d33ffffffff391932bf6fc8bf95b059625c05389f4135d788271c963b68 }

condition:
	$a0
}

        
