rule Win_Downloader_Small_3435
{
strings:
	$a0 = { 9ceb06cf64a511ba27a38cf6c77b05f0c69620f08b9cd2c440a65d14f359cbd0aaf4ed5e5940033131ad291515ca6ee02407712d05f6988f003331d88aacf365d9361aa7e1ace223cb0c04bbd702986f2bedc12d03 }

condition:
	$a0
}

        
