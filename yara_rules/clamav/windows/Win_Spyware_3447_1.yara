rule Win_Spyware_3447_1
{
strings:
	$a0 = { 9c33b407ffafa37b9e2f5dbadf6b547e1662d7478662a543c0f862a89ff69a01321cb26bc2c63bd27676ef4329ef9b422db51f10d05b359ad0f7816ceabccaac3e7e867a571e4cb4f12721ab6590b577fae58c0b3dd7fc9869fb38c6a5818fbecf23a182906ba20efa69235d51a8b1d9302702e4876478f6e0848e24e3d1802b6210d21b327ae89d5ecb8035e4bbf85b3f2c5aa26c }

condition:
	$a0
}

        