rule Win_Downloader_Agent_32545
{
strings:
	$a0 = { b60c19b10d97e6e2c1e15905523b091cc50b7b416bbab6de7415f01403ff952e803651ef0bccec55da5eb2b59a7a08e60d6fc68cfd4900cd9cb690e865495732a0221f55b0324d82829f1863b5adc741c10751a74d68b6912f7a6180f155650654710a968e000d5e6a6658180922772f89930c8f2c41c164dc6f75b5c1b39ded6c3d5a0f573148adfb08aaeb580964a56d6bb685 }

condition:
	$a0
}

        