rule Win_Trojan_Small_3722
{
strings:
	$a0 = { b133e62f2d470e2a84d9ce2c9657e1192ec4b54b316fcd5cf287cc4e5287ccef367f0dda8dcd2a3587322431966fddd92ed9d5d843a7dd192ebfccef6a7f0ddab95f38da989223442e6ee32d3eafcd5eeee3ff646b9fdd192ec5ccb1b32f42ff846ea55aaa9fcc36a37723d905f0310a2d7035 }

condition:
	$a0
}

        
