rule Win_Worm_Mytob_5
{
strings:
	$a0 = { 1ac78710f9ab924b0b57cd0177c166b93dcd99e844337f2b359e8d376fefe8c0831a20fc98c14468d7ff2cd9315077c5f4908daa5d48abeafc3490a4edebfb45254ba2318c1cbced14dbb26937101a5c63cfcb2657adb0b0714d0550ae2f668630c99b975c277bfead0f724411b03773dfeb2d54d4da6f9db56c988428b526dd347df4654294c3c1acd51eabf049f62dc66788498fda }

condition:
	$a0
}

        