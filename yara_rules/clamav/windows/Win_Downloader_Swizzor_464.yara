rule Win_Downloader_Swizzor_464
{
strings:
	$a0 = { ae8759ec597f7d490cb21bd15ffc8aea108d753086dbfc15981f993eb0f980ca6374c2f5324c635f1d6443e128db45f0110c43ac74af46dcf4572e117bc17a7fc4e932b0bc1ff786c71bd46b54956f9be12469a1be9b63b05b8a }

condition:
	$a0
}

        
